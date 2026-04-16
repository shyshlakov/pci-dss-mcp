// Package panscanner implements the PAN/cardholder data scanner that detects
// PAN/CVV exposure in Go source files and.env configuration files.
//
// Detection rules:
// - PAN-KEYWORD: Sensitive variable/field/param names with context scoring
// - PAN-TYPE: CVV/PAN fields declared as string instead of []byte
// - PAN-ZEROING: Missing explicit zeroing of []byte sensitive data
// - PAN-LITERAL: String literals matching Luhn+IIN validation
// - PAN-LOGGER: Logger calls with sensitive data arguments
package panscanner

import (
	"bufio"
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// inferPackagePathWarnOnce gates the slog.Warn in inferPackagePath so a
// persistent relative-root regression is audible exactly once per process
// instead of spamming per-file.
var inferPackagePathWarnOnce sync.Once

// defaultExcludePatterns are excluded by default.
var defaultExcludePatterns = []string{
	"vendor/",
	"generated/",
	"*.pb.go",
	"testdata/",
	"mocks/",
}

// paymentIndicators are field/param names that indicate payment context.
// Two or more in the same struct/function -> HIGH confidence.
var paymentIndicators = map[string]bool{
	"amount":      true,
	"currency":    true,
	"merchant":    true,
	"transaction": true,
	"card":        true,
	"billing":     true,
	"payment":     true,
	"price":       true,
	"fee":         true,
}

// loggerPatterns are function call patterns checked for sensitive data logging.
var loggerPatterns = []string{
	"fmt.Printf", "fmt.Fprintf", "fmt.Sprintf",
	"log.Printf", "log.Println",
	"slog.Info", "slog.Warn", "slog.Error", "slog.Debug",
}

// digitRegex matches strings containing only digits with 13-19 length.
var digitRegex = regexp.MustCompile(`^\d{13,19}$`)

// PANScanner detects PAN/CVV exposure in Go source and config files.
type PANScanner struct{}

// New creates a new PANScanner instance.
func New() *PANScanner {
	return &PANScanner{}
}

// Name implements scanner.Scanner.
func (s *PANScanner) Name() string {
	return "pan_data"
}

// Description implements scanner.Scanner.
func (s *PANScanner) Description() string {
	return "Detect PAN/CVV exposure in Go source and config files"
}

// Requirements implements scanner.Scanner.
func (s *PANScanner) Requirements() []string {
	return []string{"3.3.1", "3.4.1", "3.5.1"}
}

// Scan implements scanner.Scanner. It walks the target path for.go and.env
// files and applies all PAN detection rules. Uses default exclude patterns.
func (s *PANScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *PANScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
// Kept for compatibility with reportscanner.fullScanner; delegates to ScanFullWithTaint
// with includeTaint=false so existing callers see byte-identical behavior.
func (s *PANScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	return s.ScanFullWithTaint(ctx, targetPath, excludePatterns, includeTests, includeUntracked, false)
}

// ScanFullWithTaint runs a full panscanner pass with optional flow-based severity
// adjustment via the internal/taint engine. When includeTaint=true, the scanner
// builds a map[finding-index]taint.Source for every PAN-KEYWORD / PAN-TYPE finding
// derived from a struct field, then calls adjustSeverityByTaint to downgrade or
// suppress findings on transit-only CHD. When includeTaint=false the
// fieldSources map is not built, the bridge is not called, and the output is
// byte-identical to — graceful degradation is always-on.
func (s *PANScanner) ScanFullWithTaint(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool, includeTaint bool) (*scanner.ScanResult, error) {
	start := time.Now()

	// Absolutize targetPath before any downstream path math so inferPackagePath,
	// the walker, and taint.GetOrInit all see consistent absolute strings. Git
	// walker yields absolute file paths, and filepath.Rel(rel, abs) errors out
	// silently — the resulting empty package breaks the taint bridge. Mirrors
	// the same pattern in internal/taint/engine.go GetOrInit.
	if absRoot, absErr := filepath.Abs(targetPath); absErr == nil {
		targetPath = absRoot
	}

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	// fieldSources keys are indices into result.Findings; only PAN-KEYWORD /
	// PAN-TYPE findings derived from struct fields are tracked. Nil when
	// includeTaint=false so the existing fast path pays zero allocation.
	var fieldSources map[int]taint.Source
	if includeTaint {
		fieldSources = make(map[int]taint.Source)
	}

	// modulePath is resolved lazily on first.go file: reading go.mod once
	// per scan keeps the per-file path mapping cheap.
	modulePath := ""
	moduleResolved := false

	cfg := scanner.WalkConfig{
		Extensions:   []string{".go", ".env"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}

	walker := scanner.GitTrackedFiles
	if includeUntracked {
		walker = scanner.WalkFiles
	}
	for path, err := range walker(targetPath, cfg) {
		// Check for context cancellation between files.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err != nil {
			return nil, fmt.Errorf("walking files: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".go":
			findings, sources, lines, scanErr := scanGoFile(path)
			if scanErr != nil {
				return nil, fmt.Errorf("scanning %s: %w", path, scanErr)
			}
			if fieldSources != nil {
				if !moduleResolved {
					modulePath = readModulePath(targetPath)
					moduleResolved = true
				}
				baseIdx := len(result.Findings)
				for i, src := range sources {
					if src.TypeName == "" || src.Field == "" {
						continue
					}
					// Derive the import path now that we have the module root.
					pkgPath := inferPackagePath(targetPath, modulePath, path)
					src.Package = pkgPath
					fieldSources[baseIdx+i] = src
				}
			}
			result.Findings = append(result.Findings, findings...)
			result.Metadata.ScannedFiles++
			result.Metadata.ScannedLines += lines
		case ".env":
			findings, lines, scanErr := scanEnvFile(path)
			if scanErr != nil {
				return nil, fmt.Errorf("scanning %s: %w", path, scanErr)
			}
			result.Findings = append(result.Findings, findings...)
			result.Metadata.ScannedFiles++
			result.Metadata.ScannedLines += lines
		}
	}

	// Apply taint-based severity adjustment when requested AND we collected at
	// least one resolvable field source. The bridge handles all rules
	// PAN-TYPE suppression, and engine-unavailable fall-through.
	if includeTaint && len(fieldSources) > 0 {
		result.Findings = adjustSeverityByTaint(ctx, targetPath, result.Findings, fieldSources)
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// readModulePath reads <projectRoot>/go.mod and returns the module path declared
// on the "module..." line. Returns "" when the file is missing or unparseable
// in that case fieldSources will have empty Package values and the taint engine
// will return false (inconclusive), which the bridge maps to "keep severity".
func readModulePath(projectRoot string) string {
	f, err := os.Open(filepath.Join(projectRoot, "go.mod"))
	if err != nil {
		return ""
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close go.mod", "path", projectRoot, "err", cerr)
		}
	}()
	scn := bufio.NewScanner(f)
	for scn.Scan() {
		line := strings.TrimSpace(scn.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module"))
		}
	}
	return ""
}

// inferPackagePath derives a Go import path from a file path inside a module.
// Returns "" when the module path is empty or the file is not under projectRoot.
// Used by ScanFullWithTaint to populate taint.Source.Package without paying the
// cost of a second packages.Load.
func inferPackagePath(projectRoot, modulePath, filePath string) string {
	if modulePath == "" {
		return ""
	}
	rel, err := filepath.Rel(projectRoot, filepath.Dir(filePath))
	if err != nil {
		inferPackagePathWarnOnce.Do(func() {
			slog.Warn("inferPackagePath: cannot resolve package from absolute file relative to relative project root — taint bridge degraded",
				"project_root", projectRoot,
				"file", filePath,
				"error", err)
		})
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." {
		return modulePath
	}
	return modulePath + "/" + rel
}

// panAssignInfo records a variable → string literal assignment so
// string-literal PAN findings can be upgraded to CRITICAL when the literal
// flows into a sensitive-named variable.
type panAssignInfo struct {
	varName string
	pos     token.Pos
}

// panStructTagMeta captures which struct-tag families a struct uses, so the
// taint bridge can apply the json/db tag heuristic without re-parsing tags.
type panStructTagMeta struct {
	hasJSON bool
	hasDB   bool
}

// panScanState bundles per-file scan state so scanGoFile can split its passes
// across helper methods without threading many parameters through each call.
type panScanState struct {
	path            string
	file            *ast.File
	fset            *token.FileSet
	findings        []scanner.Finding
	sources         []taint.Source
	assignMap       map[token.Pos]panAssignInfo
	structTypeNames map[*ast.StructType]string
	structTags      map[*ast.StructType]panStructTagMeta
}

// scanGoFile parses a Go source file and applies all PAN detection rules.
// Returns findings, a parallel taint.Source slice (one entry per finding,
// zero-value for findings that are NOT struct-field-derived PAN-KEYWORD /
// PAN-TYPE), the scanned line count, and any error. The parallel sources
// slice powers the taint bridge in ScanFullWithTaint without
// disturbing the existing finding-construction code paths.
func scanGoFile(path string) ([]scanner.Finding, []taint.Source, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		return nil, nil, 0, err
	}
	if ast.IsGenerated(file) {
		return nil, nil, 0, nil
	}
	lineCount := fset.Position(file.End()).Line

	s := &panScanState{
		path:            path,
		file:            file,
		fset:            fset,
		assignMap:       map[token.Pos]panAssignInfo{},
		structTypeNames: map[*ast.StructType]string{},
		structTags:      map[*ast.StructType]panStructTagMeta{},
	}

	s.buildAssignMap()
	s.buildStructMetadata()
	s.scanStructFields()
	s.findings, s.sources = deduplicateStructFindings(s.findings, s.sources)
	s.scanFunctionParams()
	s.findings, s.sources = groupParameterFindings(s.findings, s.sources)
	s.scanStringLiteralPANs()
	s.scanLoggerCalls()
	s.scanLocalByteZeroing()

	return s.findings, s.sources, lineCount, nil
}

// appendField records a finding whose source is a named struct field, keeping
// findings and the parallel taint.Source slice in lockstep.
func (s *panScanState) appendField(f scanner.Finding, typeName, fieldName string, enclosingStruct *ast.StructType) {
	meta := s.structTags[enclosingStruct]
	s.findings = append(s.findings, f)
	s.sources = append(s.sources, taint.Source{
		TypeName:   typeName,
		Field:      fieldName,
		HasJSONTag: meta.hasJSON,
		HasDBTag:   meta.hasDB,
	})
}

// appendOther records a finding that is not tied to a specific struct field.
func (s *panScanState) appendOther(f scanner.Finding) {
	s.findings = append(s.findings, f)
	s.sources = append(s.sources, taint.Source{})
}

// buildAssignMap indexes var/const declarations and assign statements that
// bind a string literal to an identifier, keyed by the literal's Pos, so
// PAN-LITERAL findings can be upgraded to CRITICAL when the literal is bound
// to a sensitive-named variable.
func (s *panScanState) buildAssignMap() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, val := range node.Values {
				if i >= len(node.Names) {
					continue
				}
				lit, ok := val.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				s.assignMap[lit.Pos()] = panAssignInfo{
					varName: node.Names[i].Name,
					pos:     node.Names[i].Pos(),
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) {
					continue
				}
				ident, ok := node.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				lit, litOk := rhs.(*ast.BasicLit)
				if !litOk || lit.Kind != token.STRING {
					continue
				}
				s.assignMap[lit.Pos()] = panAssignInfo{
					varName: ident.Name,
					pos:     ident.Pos(),
				}
			}
		}
		return true
	})
}

// buildStructMetadata pre-computes the struct type name map and struct-tag
// family classification. Anonymous struct literals stay nameless.
func (s *panScanState) buildStructMetadata() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name == nil {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		s.structTypeNames[st] = ts.Name.Name
		s.structTags[st] = classifyStructTags(st)
		return true
	})
}

// classifyStructTags reports which tag families a struct uses so the taint
// bridge can apply the json/db heuristic without re-parsing tags.
func classifyStructTags(st *ast.StructType) panStructTagMeta {
	var meta panStructTagMeta
	if st.Fields == nil {
		return meta
	}
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}
		raw := field.Tag.Value
		if len(raw) >= 2 && raw[0] == '`' && raw[len(raw)-1] == '`' {
			raw = raw[1 : len(raw)-1]
		}
		tag := reflect.StructTag(raw)
		if _, ok := tag.Lookup("json"); ok {
			meta.hasJSON = true
		}
		for _, dbKey := range []string{"gorm", "db", "bun", "sql"} {
			if _, ok := tag.Lookup(dbKey); ok {
				meta.hasDB = true
				break
			}
		}
	}
	return meta
}

// scanStructFields walks every struct literal in the file and emits
// PAN-KEYWORD / PAN-TYPE findings based on field name + type + context score.
func (s *panScanState) scanStructFields() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		typeName := s.structTypeNames[st]
		paymentCount := countPaymentIndicatorsInFields(st.Fields.List)
		for _, field := range st.Fields.List {
			s.emitFieldFindings(field, st, typeName, paymentCount)
			s.emitJSONTagFindings(field, st, typeName)
		}
		return true
	})
}

// emitFieldFindings emits PAN-KEYWORD and PAN-TYPE findings for each named
// identifier on a struct field that matches a sensitive keyword.
func (s *panScanState) emitFieldFindings(field *ast.Field, st *ast.StructType, typeName string, paymentCount int) {
	for _, ident := range field.Names {
		if !IsSensitiveKeyword(ident.Name) {
			continue
		}
		pos := s.fset.Position(ident.Pos())
		typeStr := typeExprString(field.Type)

		finding := s.buildKeywordFinding(ident.Name, pos, paymentCount)
		if Normalize(ident.Name) == "accountnumber" && IsBankingContext(st, typeName, s.path) {
			finding.Severity = scanner.SeverityInfo
			finding.TriageHint = "banking_domain"
		}
		s.appendField(finding, typeName, ident.Name, st)

		if typeStr == "string" {
			s.appendField(scanner.Finding{
				RuleID:        "PAN-TYPE",
				Severity:      scanner.SeverityMedium,
				RequirementID: "3.5.1",
				FilePath:      s.path,
				Line:          pos.Line,
				Column:        pos.Column,
				Description:   fmt.Sprintf("Sensitive field '%s' declared as string -- immutable strings cannot be zeroed in memory", ident.Name),
				Suggestion:    "Use []byte instead of string for sensitive cardholder data to enable secure memory clearing.",
			}, typeName, ident.Name, st)
		}
	}
}

// buildKeywordFinding constructs a PAN-KEYWORD finding whose severity depends
// on the enclosing struct's payment-context score (>= 2 => CRITICAL, else HIGH).
func (s *panScanState) buildKeywordFinding(fieldName string, pos token.Position, paymentCount int) scanner.Finding {
	if paymentCount >= 2 {
		return scanner.Finding{
			RuleID:              "PAN-KEYWORD",
			Severity:            scanner.SeverityCritical,
			RequirementID:       "3.3.1",
			FilePath:            s.path,
			Line:                pos.Line,
			Column:              pos.Column,
			Description:         fmt.Sprintf("Struct field '%s' exposes cardholder data in payment context (HIGH confidence)", fieldName),
			Suggestion:          "Use tokenized or encrypted references instead of raw cardholder data.",
			RelatedRequirements: []string{"3.3.1.2"},
		}
	}
	return scanner.Finding{
		RuleID:              "PAN-KEYWORD",
		Severity:            scanner.SeverityHigh,
		RequirementID:       "3.3.1",
		FilePath:            s.path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         fmt.Sprintf("Struct field '%s' may expose cardholder data, requires manual review (LOW confidence)", fieldName),
		Suggestion:          "Verify if this field contains actual cardholder data. Use tokenized references if so.",
		RelatedRequirements: []string{"3.3.1.2"},
	}
}

// emitJSONTagFindings flags struct fields whose json tag matches a sensitive
// keyword even when the Go field name does not, so DTOs that rename fields for
// serialization still surface on the API surface.
func (s *panScanState) emitJSONTagFindings(field *ast.Field, st *ast.StructType, typeName string) {
	if field.Tag == nil {
		return
	}
	jsonTag := extractJSONTag(field.Tag.Value)
	if jsonTag == "" || !IsSensitiveKeyword(jsonTag) {
		return
	}
	pos := s.fset.Position(field.Tag.Pos())
	fieldName := jsonTag
	if len(field.Names) > 0 {
		fieldName = field.Names[0].Name
	}
	s.appendField(scanner.Finding{
		RuleID:              "PAN-KEYWORD",
		Severity:            scanner.SeverityHigh,
		RequirementID:       "3.3.1",
		FilePath:            s.path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         fmt.Sprintf("Struct field json tag '%s' exposes cardholder data keyword", jsonTag),
		Suggestion:          "Rename the JSON field or use a DTO without sensitive field names in API responses.",
		RelatedRequirements: []string{"3.3.1.2"},
	}, typeName, fieldName, st)
}

// scanFunctionParams emits PAN-TYPE findings for function / func-literal
// parameters declared with a sensitive name and string type. PAN-KEYWORD is
// deliberately suppressed for parameters because it is pure noise at scale.
func (s *panScanState) scanFunctionParams() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		params, funcName, ok := funcParams(n)
		if !ok || params == nil {
			return true
		}
		for _, field := range params.List {
			if typeExprString(field.Type) != "string" {
				continue
			}
			for _, ident := range field.Names {
				if !IsSensitiveKeyword(ident.Name) {
					continue
				}
				pos := s.fset.Position(ident.Pos())
				s.appendOther(scanner.Finding{
					RuleID:        "PAN-TYPE",
					Severity:      scanner.SeverityMedium,
					RequirementID: "3.5.1",
					FilePath:      s.path,
					Line:          pos.Line,
					Column:        pos.Column,
					Description:   fmt.Sprintf("Sensitive parameter '%s' declared as string in %s -- immutable strings cannot be zeroed in memory", ident.Name, funcName),
					Suggestion:    "Use []byte instead of string for sensitive cardholder data to enable secure memory clearing.",
				})
			}
		}
		return true
	})
}

// funcParams returns the parameter list and display name for a FuncDecl or
// FuncLit. It reports ok=false for any other AST node.
func funcParams(n ast.Node) (*ast.FieldList, string, bool) {
	switch node := n.(type) {
	case *ast.FuncDecl:
		return node.Type.Params, node.Name.Name, true
	case *ast.FuncLit:
		return node.Type.Params, "<anonymous>", true
	}
	return nil, "", false
}

// scanStringLiteralPANs flags string literals whose digits pass Luhn+IIN
// validation, upgrading to CRITICAL when the literal binds to a
// sensitive-named variable via assignMap.
func (s *panScanState) scanStringLiteralPANs() {
	for _, m := range scanner.InspectStringLiterals(s.file, s.fset, digitRegex) {
		if !IsLikelyPAN(m.Value) {
			continue
		}
		severity, desc := s.classifyLiteralPAN(m)
		s.appendOther(scanner.Finding{
			RuleID:        "PAN-LITERAL",
			Severity:      severity,
			RequirementID: "3.4.1",
			FilePath:      s.path,
			Line:          m.Position.Line,
			Column:        m.Position.Column,
			Description:   desc,
			Suggestion:    "Remove hardcoded card numbers. Use tokenized references or test card number constants.",
		})
	}
}

// classifyLiteralPAN returns the severity and description for a PAN literal,
// upgrading to CRITICAL when the literal's position matches a sensitive-named
// variable binding recorded in assignMap.
func (s *panScanState) classifyLiteralPAN(m scanner.StringMatch) (scanner.Severity, string) {
	severity := scanner.SeverityMedium
	desc := "String literal resembles a PAN (Luhn+IIN valid), requires manual review"
	if info, ok := s.assignMap[s.fset.File(s.file.Pos()).Pos(m.Position.Offset+1)]; ok {
		if IsSensitiveKeyword(info.varName) {
			return scanner.SeverityCritical, fmt.Sprintf("PAN literal assigned to sensitive variable '%s' (HIGH confidence)", info.varName)
		}
	}
	for litPos, info := range s.assignMap {
		litFilePos := s.fset.Position(litPos)
		if litFilePos.Line != m.Position.Line || litFilePos.Filename != m.Position.Filename {
			continue
		}
		if IsSensitiveKeyword(info.varName) {
			return scanner.SeverityCritical, fmt.Sprintf("PAN literal assigned to sensitive variable '%s' (HIGH confidence)", info.varName)
		}
	}
	return severity, desc
}

// scanLoggerCalls flags sensitive identifiers passed as arguments to known
// logger functions (Println, Printf, slog, logrus, etc).
func (s *panScanState) scanLoggerCalls() {
	for _, cm := range scanner.InspectCalls(s.file, s.fset, loggerPatterns...) {
		for _, arg := range cm.Args {
			ident, ok := arg.(*ast.Ident)
			if !ok || !IsSensitiveKeyword(ident.Name) {
				continue
			}
			s.appendOther(scanner.Finding{
				RuleID:        "PAN-LOGGER",
				Severity:      scanner.SeverityCritical,
				RequirementID: "3.3.1",
				FilePath:      s.path,
				Line:          cm.Position.Line,
				Column:        cm.Position.Column,
				Description:   fmt.Sprintf("Sensitive cardholder data '%s' passed to logging function %s", ident.Name, cm.FuncName),
				Suggestion:    "Remove sensitive data from log output. Log a masked or tokenized reference instead.",
			})
		}
	}
}

// scanLocalByteZeroing walks function bodies for sensitive []byte locals that
// are not explicitly zeroed before they go out of scope.
func (s *panScanState) scanLocalByteZeroing() {
	ast.Inspect(s.file, func(n ast.Node) bool {
		body := funcBody(n)
		if body == nil {
			return true
		}
		for _, v := range s.collectLocalSensitiveByteVars(body) {
			if hasZeroingPattern(body, v.name) {
				continue
			}
			s.appendOther(scanner.Finding{
				RuleID:        "PAN-ZEROING",
				Severity:      scanner.SeverityMedium,
				RequirementID: "3.5.1",
				FilePath:      s.path,
				Line:          v.pos.Line,
				Column:        v.pos.Column,
				Description:   fmt.Sprintf("Sensitive []byte data '%s' not explicitly zeroed after use", v.name),
				Suggestion:    "Add explicit zeroing: for i := range data { data[i] = 0 } or use clear(data) after use.",
			})
		}
		return true
	})
}

// funcBody returns the body of a FuncDecl or FuncLit, or nil otherwise.
func funcBody(n ast.Node) *ast.BlockStmt {
	switch node := n.(type) {
	case *ast.FuncDecl:
		return node.Body
	case *ast.FuncLit:
		return node.Body
	}
	return nil
}

// localSensitiveByte names a sensitive []byte local with its declaration
// position — enough context to emit a PAN-ZEROING finding.
type localSensitiveByte struct {
	name string
	pos  token.Position
}

// collectLocalSensitiveByteVars walks a function body for sensitive-named
// []byte locals created via short-assign or var declarations.
func (s *panScanState) collectLocalSensitiveByteVars(body *ast.BlockStmt) []localSensitiveByte {
	var locals []localSensitiveByte
	ast.Inspect(body, func(inner ast.Node) bool {
		switch stmt := inner.(type) {
		case *ast.AssignStmt:
			for i, lhs := range stmt.Lhs {
				ident, ok := lhs.(*ast.Ident)
				if !ok || !IsSensitiveKeyword(ident.Name) {
					continue
				}
				if i < len(stmt.Rhs) && isByteSliceExpr(stmt.Rhs[i]) {
					locals = append(locals, localSensitiveByte{
						name: ident.Name,
						pos:  s.fset.Position(ident.Pos()),
					})
				}
			}
		case *ast.ValueSpec:
			for _, ident := range stmt.Names {
				if !IsSensitiveKeyword(ident.Name) {
					continue
				}
				if stmt.Type != nil && typeExprString(stmt.Type) == "[]byte" {
					locals = append(locals, localSensitiveByte{
						name: ident.Name,
						pos:  s.fset.Position(ident.Pos()),
					})
				}
			}
		}
		return true
	})
	return locals
}

// countPaymentIndicatorsInFields counts how many fields in the list match
// payment context indicators.
func countPaymentIndicatorsInFields(fields []*ast.Field) int {
	count := 0
	for _, field := range fields {
		for _, ident := range field.Names {
			normalized := Normalize(ident.Name)
			if paymentIndicators[normalized] {
				count++
			}
		}
	}
	return count
}

// typeExprString returns a best-effort string representation of a type expression.
func typeExprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + typeExprString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeExprString(t.Elt)
		}
	case *ast.MapType:
		return "map[" + typeExprString(t.Key) + "]" + typeExprString(t.Value)
	}
	return fmt.Sprintf("%T", expr)
}

// extractJSONTag extracts the json field name from a struct tag string.
// e.g., `json:"card_number"` -> "card_number"
// e.g., `json:"card_number,omitempty"` -> "card_number"
func extractJSONTag(rawTag string) string {
	// Remove backticks.
	tag := strings.Trim(rawTag, "`")
	// Use reflect.StructTag for robust parsing.
	jsonVal := reflect.StructTag(tag).Get("json")
	if jsonVal == "" || jsonVal == "-" {
		return ""
	}
	// Strip options like ",omitempty".
	if idx := strings.Index(jsonVal, ","); idx != -1 {
		jsonVal = jsonVal[:idx]
	}
	return jsonVal
}

// isByteSliceExpr checks if an expression is a []byte(...) conversion or
// similar pattern indicating a []byte value.
func isByteSliceExpr(expr ast.Expr) bool {
	// Check for []byte("...") conversion.
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	// Check if the function is a type conversion to []byte.
	arrType, ok := call.Fun.(*ast.ArrayType)
	if !ok {
		return false
	}
	if arrType.Len != nil {
		return false
	}
	ident, ok := arrType.Elt.(*ast.Ident)
	return ok && ident.Name == "byte"
}

// hasZeroingPattern checks if a function body contains a zeroing pattern for
// the given variable name. Recognizes two patterns:
// 1. for i:= range varName { varName[i] = 0 }
// 2. clear(varName)
func hasZeroingPattern(body *ast.BlockStmt, varName string) bool {
	var found bool
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch node := n.(type) {
		case *ast.RangeStmt:
			// Check if ranging over our variable.
			if ident, ok := node.X.(*ast.Ident); ok && ident.Name == varName {
				// Check if body assigns 0 to indexed element.
				if hasZeroAssignment(node.Body, varName) {
					found = true
					return false
				}
			}
		case *ast.CallExpr:
			// Check for clear(varName).
			if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "clear" {
				if len(node.Args) == 1 {
					if arg, ok := node.Args[0].(*ast.Ident); ok && arg.Name == varName {
						found = true
						return false
					}
				}
			}
		}
		return true
	})
	return found
}

// deduplicateStructFindings merges PAN-KEYWORD findings on the same (FilePath, Line)
// where both struct field name and json tag triggered. Keeps 1 finding with merged
// description. If the two findings have different keyword sources (different
// sensitive keywords), keep both. Operates on the parallel findings/sources slices
// so the taint bridge sees a consistent index map.
func deduplicateStructFindings(findings []scanner.Finding, sources []taint.Source) ([]scanner.Finding, []taint.Source) {
	type key struct {
		FilePath string
		Line     int
	}
	groups := map[key][]int{} // key -> indices of PAN-KEYWORD findings
	for i, f := range findings {
		if f.RuleID != "PAN-KEYWORD" {
			continue
		}
		k := key{f.FilePath, f.Line}
		groups[k] = append(groups[k], i)
	}

	remove := map[int]bool{}
	for _, indices := range groups {
		if len(indices) < 2 {
			continue
		}
		// Find field-name and json-tag findings.
		fieldIdx, tagIdx := -1, -1
		for _, idx := range indices {
			desc := findings[idx].Description
			if strings.Contains(desc, "json tag") {
				tagIdx = idx
			} else if strings.Contains(desc, "Struct field") {
				fieldIdx = idx
			}
		}
		if fieldIdx < 0 || tagIdx < 0 {
			continue
		}

		// If the field and tag reference different sensitive keywords, keep both.
		fieldName := extractQuotedName(findings[fieldIdx].Description)
		tagName := extractQuotedName(findings[tagIdx].Description)
		if Normalize(fieldName) != Normalize(tagName) {
			continue
		}

		// Merge: keep the field finding, update description, remove the tag finding.
		findings[fieldIdx].Description = fmt.Sprintf(
			"Struct field '%s' (json: '%s') may expose cardholder data",
			fieldName, tagName,
		)
		if severityHigher(findings[tagIdx].Severity, findings[fieldIdx].Severity) {
			findings[fieldIdx].Severity = findings[tagIdx].Severity
		}
		// If the kept finding has no source but the dropped tag finding does
		// (or vice-versa), promote the populated one so the bridge can still
		// resolve the field. Both should normally be set; this is defensive.
		if sources != nil && fieldIdx < len(sources) && tagIdx < len(sources) {
			if sources[fieldIdx].TypeName == "" && sources[tagIdx].TypeName != "" {
				sources[fieldIdx] = sources[tagIdx]
			}
		}
		remove[tagIdx] = true
	}

	var resultFindings []scanner.Finding
	var resultSources []taint.Source
	for i, f := range findings {
		if remove[i] {
			continue
		}
		resultFindings = append(resultFindings, f)
		if sources != nil && i < len(sources) {
			resultSources = append(resultSources, sources[i])
		}
	}
	return resultFindings, resultSources
}

// groupParameterFindings groups PAN-TYPE findings with the same
// (FilePath, ParameterName) into a single finding with function count.
// : per-file grouping only. Operates on the parallel findings/sources
// slices introduced in so the taint bridge sees a consistent index map.
func groupParameterFindings(findings []scanner.Finding, sources []taint.Source) ([]scanner.Finding, []taint.Source) {
	type key struct {
		FilePath  string
		ParamName string
	}
	groups := map[key][]int{}
	for i, f := range findings {
		if f.RuleID != "PAN-TYPE" || !strings.Contains(f.Description, "parameter") {
			continue
		}
		paramName := extractParamName(f.Description)
		if paramName == "" {
			continue
		}
		k := key{f.FilePath, paramName}
		groups[k] = append(groups[k], i)
	}

	remove := map[int]bool{}
	for _, indices := range groups {
		if len(indices) < 2 {
			continue
		}
		// Collect function names from descriptions.
		var funcNames []string
		for _, idx := range indices {
			fn := extractFuncName(findings[idx].Description)
			if fn != "" {
				funcNames = append(funcNames, fn)
			}
		}

		// Keep first, merge others into it.
		paramName := extractParamName(findings[indices[0]].Description)
		if len(funcNames) > 0 {
			findings[indices[0]].Description = fmt.Sprintf(
				"Sensitive parameter '%s' declared as string in %d functions (%s) -- immutable strings cannot be zeroed in memory",
				paramName, len(indices), strings.Join(funcNames, ", "),
			)
		} else {
			findings[indices[0]].Description = fmt.Sprintf(
				"Sensitive parameter '%s' declared as string in %d functions -- immutable strings cannot be zeroed in memory",
				paramName, len(indices),
			)
		}

		// Keep highest severity.
		for _, idx := range indices[1:] {
			if severityHigher(findings[idx].Severity, findings[indices[0]].Severity) {
				findings[indices[0]].Severity = findings[idx].Severity
			}
			remove[idx] = true
		}
	}

	var resultFindings []scanner.Finding
	var resultSources []taint.Source
	for i, f := range findings {
		if remove[i] {
			continue
		}
		resultFindings = append(resultFindings, f)
		if sources != nil && i < len(sources) {
			resultSources = append(resultSources, sources[i])
		}
	}
	return resultFindings, resultSources
}

// extractQuotedName extracts the first single-quoted name from a string.
// e.g., "Struct field 'CVV' may expose..." -> "CVV"
// e.g., "Struct field json tag 'cvv' exposes..." -> "cvv"
func extractQuotedName(s string) string {
	start := strings.Index(s, "'")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start+1:], "'")
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}

// extractParamName extracts the parameter name from a PAN-TYPE description.
// e.g., "Sensitive parameter 'cardNumber' declared as string in maskCard..." -> "cardNumber"
func extractParamName(desc string) string {
	const prefix = "Sensitive parameter '"
	idx := strings.Index(desc, prefix)
	if idx < 0 {
		return ""
	}
	rest := desc[idx+len(prefix):]
	end := strings.Index(rest, "'")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// extractFuncName extracts the function name from a PAN-TYPE description.
// e.g., "Sensitive parameter 'cardNumber' declared as string in maskCard --..." -> "maskCard"
func extractFuncName(desc string) string {
	const marker = "declared as string in "
	idx := strings.Index(desc, marker)
	if idx < 0 {
		return ""
	}
	rest := desc[idx+len(marker):]
	// Function name ends at " --" or " (" or end of string
	for _, sep := range []string{" --", " ("} {
		if i := strings.Index(rest, sep); i >= 0 {
			rest = rest[:i]
			break
		}
	}
	return strings.TrimSpace(rest)
}

// severityHigher returns true if a is higher severity than b.
func severityHigher(a, b scanner.Severity) bool {
	return severityRank(a) > severityRank(b)
}

// severityRank returns a numeric rank for severity ordering.
func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 5
	case scanner.SeverityHigh:
		return 4
	case scanner.SeverityMedium:
		return 3
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 1
	default:
		return 0
	}
}

// hasZeroAssignment checks if a block contains an assignment of 0 to an indexed
// element of varName.
func hasZeroAssignment(body *ast.BlockStmt, varName string) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range assign.Lhs {
			idx, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			if ident, ok := idx.X.(*ast.Ident); ok && ident.Name == varName {
				// Check if RHS is 0.
				if i < len(assign.Rhs) {
					if lit, ok := assign.Rhs[i].(*ast.BasicLit); ok && lit.Value == "0" {
						return true
					}
				}
			}
		}
	}
	return false
}
