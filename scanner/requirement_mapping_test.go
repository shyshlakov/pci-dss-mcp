package scanner_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Go's //go:embed directive cannot escape the package directory, so the docs
// table living at docs/requirement-mapping.md is loaded via runtime.Caller +
// os.ReadFile. The fail-on-missing-docs guarantee is preserved: loadDocsTable
// calls t.Fatalf when the file is absent or empty, which fails CI just like a
// build error would.
const (
	docsRelFromScannerPkg = "../docs/requirement-mapping.md"
	dynamicEmitWaiver     = "dynamic emit"
)

type docsRow struct {
	ruleID       string
	primary      string
	related      []string
	scanner      string
	coverage     string
	coverageNote string
}

type srcEmit struct {
	primary string
	related string
}

func (r docsRow) srcEmit() srcEmit {
	return srcEmit{primary: r.primary, related: strings.Join(r.related, ",")}
}

func (r docsRow) waived() bool {
	return strings.Contains(r.coverageNote, dynamicEmitWaiver)
}

func TestRequirementMappingGuard(t *testing.T) {
	docs := loadDocsTable(t)
	source := walkSourceEmits(t)

	t.Run("every_source_rule_has_docs_row", func(tt *testing.T) {
		checkSourceHasDocs(source, docs, tt.Errorf)
	})

	t.Run("every_docs_row_has_source_emit", func(tt *testing.T) {
		checkDocsHasSource(docs, source, tt.Errorf)
	})

	t.Run("docs_mapping_matches_source", func(tt *testing.T) {
		checkMappingMatches(docs, source, tt.Errorf)
	})
}

func TestRequirementMappingGuardSyntheticDrift(t *testing.T) {
	tt := []struct {
		name       string
		source     map[string]map[srcEmit]bool
		docs       map[string]docsRow
		check      func(map[string]docsRow, map[string]map[srcEmit]bool, func(string, ...any))
		wantErrors int
		wantSubstr string
	}{
		{
			name:   "missing_docs",
			source: map[string]map[srcEmit]bool{"RULE-X": {{primary: "3.3.1"}: true}},
			docs:   map[string]docsRow{},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkSourceHasDocs(s, d, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-X",
		},
		{
			name:   "orphan_docs",
			source: map[string]map[srcEmit]bool{},
			docs:   map[string]docsRow{"RULE-Y": {ruleID: "RULE-Y", primary: "3.3.1"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkDocsHasSource(d, s, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-Y",
		},
		{
			name:   "orphan_docs_waived",
			source: map[string]map[srcEmit]bool{},
			docs:   map[string]docsRow{"RULE-Y": {ruleID: "RULE-Y", primary: "3.3.1", coverageNote: "dynamic emit via helper"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkDocsHasSource(d, s, r)
			},
			wantErrors: 0,
		},
		{
			name:   "mapping_drift",
			source: map[string]map[srcEmit]bool{"RULE-Z": {{primary: "3.3.1"}: true}},
			docs:   map[string]docsRow{"RULE-Z": {ruleID: "RULE-Z", primary: "3.5.1"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkMappingMatches(d, s, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-Z",
		},
		{
			name:   "mapping_drift_waived",
			source: map[string]map[srcEmit]bool{"RULE-W": {{primary: "3.3.1"}: true}},
			docs:   map[string]docsRow{"RULE-W": {ruleID: "RULE-W", primary: "3.5.1", coverageNote: "dynamic emit — see source"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkMappingMatches(d, s, r)
			},
			wantErrors: 0,
		},
		{
			name:   "mapping_empty_source_no_waiver",
			source: map[string]map[srcEmit]bool{"RULE-V": {}},
			docs:   map[string]docsRow{"RULE-V": {ruleID: "RULE-V", primary: "3.5.1"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkMappingMatches(d, s, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-V",
		},
		{
			name:   "mapping_empty_source_waived",
			source: map[string]map[srcEmit]bool{"RULE-U": {}},
			docs:   map[string]docsRow{"RULE-U": {ruleID: "RULE-U", primary: "3.5.1", coverageNote: "dynamic emit"}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkMappingMatches(d, s, r)
			},
			wantErrors: 0,
		},
		{
			name:   "mapping_exact_match",
			source: map[string]map[srcEmit]bool{"RULE-T": {{primary: "3.5.1", related: "3.4.1,10.2.1"}: true}},
			docs:   map[string]docsRow{"RULE-T": {ruleID: "RULE-T", primary: "3.5.1", related: []string{"3.4.1", "10.2.1"}}},
			check: func(d map[string]docsRow, s map[string]map[srcEmit]bool, r func(string, ...any)) {
				checkMappingMatches(d, s, r)
			},
			wantErrors: 0,
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(tt *testing.T) {
			var errs []string
			c.check(c.docs, c.source, func(format string, args ...any) {
				errs = append(errs, fmt.Sprintf(format, args...))
			})
			if len(errs) != c.wantErrors {
				tt.Fatalf("got %d errors, want %d (errors: %v)", len(errs), c.wantErrors, errs)
			}
			if c.wantSubstr != "" {
				if len(errs) == 0 || !strings.Contains(errs[0], c.wantSubstr) {
					tt.Fatalf("want error to contain %q, got %v", c.wantSubstr, errs)
				}
			}
		})
	}
}

func checkSourceHasDocs(source map[string]map[srcEmit]bool, docs map[string]docsRow, report func(string, ...any)) {
	ids := make([]string, 0, len(source))
	for id := range source {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := docs[id]; !ok {
			report("source rule %q has no row in docs/requirement-mapping.md", id)
		}
	}
}

func checkDocsHasSource(docs map[string]docsRow, source map[string]map[srcEmit]bool, report func(string, ...any)) {
	ids := make([]string, 0, len(docs))
	for id := range docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := source[id]; ok {
			continue
		}
		if docs[id].waived() {
			continue
		}
		report("docs row %q has no live source emit in scanner/*/*.go (and no dynamic emit waiver)", id)
	}
}

func checkMappingMatches(docs map[string]docsRow, source map[string]map[srcEmit]bool, report func(string, ...any)) {
	ids := make([]string, 0, len(docs))
	for id := range docs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := docs[id]
		emits, ok := source[id]
		if !ok {
			continue
		}
		want := row.srcEmit()
		if emits[want] {
			continue
		}
		if row.waived() {
			continue
		}
		report("rule %q docs primary=%q related=%v not found among source emits %v",
			id, row.primary, row.related, formatEmitKeys(emits))
	}
}

func formatEmitKeys(emits map[srcEmit]bool) []string {
	out := make([]string, 0, len(emits))
	for e := range emits {
		out = append(out, fmt.Sprintf("(%s|%s)", e.primary, e.related))
	}
	sort.Strings(out)
	return out
}

func loadDocsTable(t *testing.T) map[string]docsRow {
	t.Helper()
	path := filepath.Join(scannerDir(t), docsRelFromScannerPkg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v -- docs/requirement-mapping.md is required for the drift guard", path, err)
	}
	rows := map[string]docsRow{}
	inTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			inTable = false
			continue
		}
		if strings.Contains(trimmed, "| rule_id |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if strings.HasPrefix(trimmed, "|--") || strings.HasPrefix(trimmed, "|-") {
			continue
		}
		cells := splitTableRow(trimmed)
		if len(cells) < 6 {
			continue
		}
		ruleID := strings.TrimSpace(cells[0])
		if ruleID == "" || ruleID == "rule_id" {
			continue
		}
		row := docsRow{
			ruleID:       ruleID,
			primary:      strings.TrimSpace(cells[1]),
			related:      parseRelatedCell(cells[2]),
			scanner:      strings.TrimSpace(cells[3]),
			coverage:     strings.TrimSpace(cells[4]),
			coverageNote: strings.TrimSpace(cells[5]),
		}
		if _, dup := rows[ruleID]; dup {
			t.Errorf("docs/requirement-mapping.md: duplicate row for rule_id %q", ruleID)
			continue
		}
		rows[ruleID] = row
	}
	if len(rows) == 0 {
		t.Fatalf("docs/requirement-mapping.md: parsed zero rows from embedded table")
	}
	return rows
}

func splitTableRow(line string) []string {
	if len(line) < 2 {
		return nil
	}
	body := strings.TrimPrefix(line, "|")
	body = strings.TrimSuffix(body, "|")
	parts := strings.Split(body, "|")
	return parts
}

func parseRelatedCell(cell string) []string {
	cell = strings.TrimSpace(cell)
	if cell == "" {
		return nil
	}
	out := []string{}
	for _, p := range strings.Split(cell, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func walkSourceEmits(t *testing.T) map[string]map[srcEmit]bool {
	t.Helper()
	scannerRoot := scannerDir(t)
	files := collectScannerFiles(t, scannerRoot)

	globalConst := map[string]string{}
	fset := token.NewFileSet()
	parsed := map[string]*ast.File{}
	for _, f := range files {
		src, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Logf("parse %s: %v (skipping)", f, err)
			continue
		}
		parsed[f] = src
		collectConsts(src, globalConst)
	}

	out := map[string]map[srcEmit]bool{}
	for f, src := range parsed {
		walkFindings(src, "", globalConst, func(ruleID string, resolved bool, e srcEmit) {
			if out[ruleID] == nil {
				out[ruleID] = map[srcEmit]bool{}
			}
			if resolved {
				out[ruleID][e] = true
			}
		}, func(pos token.Pos, what string) {
			p := fset.Position(pos)
			t.Logf("%s:%d: %s (unresolved, waiver required if docs row exists)", filepath.Base(f), p.Line, what)
		})
	}
	return out
}

func scannerDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller: cannot locate test source")
	}
	return filepath.Dir(thisFile)
}

func collectScannerFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == "testdata" {
				return filepath.SkipDir
			}
			if strings.HasSuffix(p, string(filepath.Separator)+"internal"+string(filepath.Separator)+"sensitivedata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk scanner dir %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("walk scanner dir %s: found zero .go files", root)
	}
	return out
}

func collectConsts(src *ast.File, dst map[string]string) {
	for _, decl := range src.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if s, ok := resolveStringExpr(vs.Values[i], dst); ok {
					dst[name.Name] = s
				}
			}
		}
	}
}

func walkFindings(
	root ast.Node,
	inheritedType string,
	globalConst map[string]string,
	emit func(ruleID string, resolved bool, e srcEmit),
	logUnresolved func(pos token.Pos, what string),
) {
	switch n := root.(type) {
	case nil:
		return
	case *ast.File:
		for _, d := range n.Decls {
			walkFindings(d, "", globalConst, emit, logUnresolved)
		}
	case *ast.CompositeLit:
		declaredType := exprTypeName(n.Type)
		effectiveType := declaredType
		if effectiveType == "" {
			effectiveType = inheritedType
		}
		if effectiveType == "Finding" {
			extractFindingLiteral(n, globalConst, emit, logUnresolved)
		}
		childInherited := ""
		switch t := n.Type.(type) {
		case *ast.ArrayType:
			childInherited = exprTypeName(t.Elt)
		case *ast.MapType:
			childInherited = exprTypeName(t.Value)
		}
		for _, elt := range n.Elts {
			walkFindings(elt, childInherited, globalConst, emit, logUnresolved)
		}
	default:
		ast.Inspect(root, func(nn ast.Node) bool {
			if nn == root {
				return true
			}
			if cl, ok := nn.(*ast.CompositeLit); ok {
				walkFindings(cl, "", globalConst, emit, logUnresolved)
				return false
			}
			return true
		})
	}
}

func extractFindingLiteral(
	cl *ast.CompositeLit,
	globalConst map[string]string,
	emit func(ruleID string, resolved bool, e srcEmit),
	logUnresolved func(pos token.Pos, what string),
) {
	var ruleID, reqID string
	var related []string
	hasRuleID, hasReqID := false, false
	reqIDUnresolved := false
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "RuleID":
			if s, ok := resolveStringExpr(kv.Value, globalConst); ok {
				ruleID = s
				hasRuleID = true
			} else {
				logUnresolved(kv.Value.Pos(), "Finding.RuleID expression not resolvable to string literal")
			}
		case "RequirementID":
			if s, ok := resolveStringExpr(kv.Value, globalConst); ok {
				reqID = s
				hasReqID = true
			} else {
				reqIDUnresolved = true
			}
		case "RelatedRequirements":
			related = resolveStringSliceExpr(kv.Value, globalConst)
		}
	}
	if !hasRuleID {
		return
	}
	if !hasReqID {
		if reqIDUnresolved {
			logUnresolved(cl.Pos(), fmt.Sprintf("Finding %q has dynamic RequirementID; docs row must carry dynamic emit waiver", ruleID))
		}
		emit(ruleID, false, srcEmit{})
		return
	}
	sort.Strings(related)
	emit(ruleID, true, srcEmit{primary: reqID, related: strings.Join(related, ",")})
}

func exprTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.StarExpr:
		return exprTypeName(t.X)
	}
	return ""
}

func resolveStringExpr(expr ast.Expr, globalConst map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s, err := strconv.Unquote(e.Value)
			if err != nil {
				return "", false
			}
			return s, true
		}
	case *ast.Ident:
		if s, ok := globalConst[e.Name]; ok {
			return s, true
		}
	case *ast.SelectorExpr:
		if s, ok := globalConst[e.Sel.Name]; ok {
			return s, true
		}
	}
	return "", false
}

func resolveStringSliceExpr(expr ast.Expr, globalConst map[string]string) []string {
	if expr == nil {
		return nil
	}
	if id, ok := expr.(*ast.Ident); ok && id.Name == "nil" {
		return nil
	}
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}
	out := []string{}
	for _, el := range cl.Elts {
		if s, ok := resolveStringExpr(el, globalConst); ok {
			out = append(out, s)
		}
	}
	return out
}
