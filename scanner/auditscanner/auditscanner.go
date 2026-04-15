// Package auditscanner detects payment HTTP handlers missing structured audit
// logging as required by PCI DSS 10.2.1.
//
// Detection rules:
// - AUDIT-NO-LOG: Payment handler with no logging at all (10.2.1)
// - AUDIT-UNSTRUCTURED: Payment handler with only unstructured logging (10.2.1)
// - AUDIT-LOG-OK: Payment handler with structured logging present (10.2.1)
package auditscanner

import (
	"context"
	"fmt"
	"go/ast"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// defaultExcludePatterns are excluded by default from scanning.
var defaultExcludePatterns = []string{
	"vendor/",
	"generated/",
	"*.pb.go",
	"testdata/",
	"mocks/",
}

// AuditScanner detects payment handlers missing structured audit logging.
type AuditScanner struct{}

// New creates a new AuditScanner instance.
func New() *AuditScanner {
	return &AuditScanner{}
}

// Name implements scanner.Scanner.
func (s *AuditScanner) Name() string {
	return "audit_log_coverage"
}

// Description implements scanner.Scanner.
func (s *AuditScanner) Description() string {
	return "Detect payment handlers missing structured audit logging (PCI DSS 10.2.1)"
}

// Requirements implements scanner.Scanner.
func (s *AuditScanner) Requirements() []string {
	return []string{"10.2.1"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *AuditScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *AuditScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *AuditScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	// Clear cross-file middleware cache per scan session.
	ResetPackageCache()
	// Clear field extraction cache per scan session (ALF-05, ).
	ResetLogFieldCache()

	start := time.Now()

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	cfg := scanner.WalkConfig{
		Extensions:   []string{".go"},
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
		if ext != ".go" {
			continue
		}

		findings, lines, scanErr := s.scanGoFile(path)
		if scanErr != nil {
			return nil, fmt.Errorf("scanning %s: %w", path, scanErr)
		}
		result.Findings = append(result.Findings, findings...)
		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// loggingMiddlewareKeywords are function/type names indicating logging middleware.
var loggingMiddlewareKeywords = []string{
	"loggingmiddleware", "auditmiddleware", "requestlogger",
}

// scanGoFile parses a single Go source file and checks all payment HTTP handlers
// for structured audit logging.
func (s *AuditScanner) scanGoFile(path string) ([]scanner.Finding, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		return nil, 0, err
	}

	// Skip generated files.
	if ast.IsGenerated(file) {
		return nil, 0, nil
	}

	lineCount := fset.Position(file.End()).Line

	// Detect framework for handler signature matching.
	fw := detector.DetectFramework(file)

	// Resolve import aliases for structured logger detection.
	aliases := resolveImportAliases(file)

	// Build same-file function map for 1-level delegation resolution.
	fileFuncs := sameFileFuncs(file)

	// Pass 1: collect all function names for Tier 3 co-location check.
	var allFuncNames []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		allFuncNames = append(allFuncNames, fn.Name.Name)
	}
	fileTier1Present := keywords.FileHasTier1Keyword(allFuncNames)

	// Map tier to severity.
	tierSeverity := map[int]scanner.Severity{
		1: scanner.SeverityCritical,
		2: scanner.SeverityHigh,
		3: scanner.SeverityMedium,
	}

	var findings []scanner.Finding

	// per-PackageInfo score cache is fresh on each
	// construction -- no global reset required.
	pkgInfo := keywords.PackageInfoFromFile(file, fset, path)

	// Pass 2: scan each function for logging.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}

		// Tier-based classification still drives severity, but the
		// admission gate is widened to the multi-signal scorer. Context
		// matches missed by PaymentFuncTier enter at Tier 2 per the
		// recall-bias philosophy.
		tier := keywords.PaymentFuncTier(fn.Name.Name, fileTier1Present)
		if tier == 0 {
			if !keywords.IsPaymentContext(fn, pkgInfo) {
				continue
			}
			tier = 2
		}

		// Skip non-HTTP handlers.
		if !detector.IsHTTPHandler(fn, fw) {
			continue
		}

		// Skip functions with no body (interface declarations, etc.).
		if fn.Body == nil {
			continue
		}

		pos := fset.Position(fn.Pos())
		handlerName := fn.Name.Name
		sev := tierSeverity[tier]

		// Check for logging in the handler body.
		hasStructured, hasUnstructured := hasStructuredLogging(fn.Body, aliases)

		// If no structured logging found directly, try 1-level delegation.
		if !hasStructured {
			hasStructured = hasStructuredLoggingInDelegates(fn.Body, fileFuncs, aliases)
		}

		switch {
		case hasStructured:
			// INFO note: structured logging detected, remind about required fields.
			// Severity stays INFO regardless of tier.
			findings = append(findings, scanner.Finding{
				RuleID:        "AUDIT-LOG-OK",
				Severity:      scanner.SeverityInfo,
				RequirementID: "10.2.1",
				FilePath:      path,
				Line:          pos.Line,
				Column:        pos.Column,
				Description: fmt.Sprintf(
					"Structured audit logging detected in payment handler %s. "+
						"Verify log captures required PCI DSS 10.2.1 fields: user_id, timestamp, "+
						"event_type, outcome, affected_resource. Not verifiable statically if using "+
						"logger.With() context pattern.",
					handlerName,
				),
				Suggestion: "Review log statements to ensure all PCI DSS 10.2.1 required fields are captured.",
			})

		default:
			// Check if handler is registered with logging middleware.
			// per-file fast path first; cross-file fallback only when fast path misses.
			if hasLoggingMiddleware(file, handlerName) || hasLoggingCoverageInPackage(path, handlerName) {
				// Downgrade to INFO -- middleware handles logging (in-file or cross-file).
				// MiddlewareDetected=true either way.
				severity := scanner.SeverityInfo
				description := fmt.Sprintf(
					"Logging middleware detected for payment handler %s. "+
						"Verify it logs required PCI DSS 10.2.1 fields: user_id, timestamp, "+
						"action, outcome, resource.",
					handlerName,
				)
				suggestion := "Verify middleware captures all required PCI DSS 10.2.1 audit fields."

				// attempt field extraction and scoring.
				middlewareImport, middlewareFunc := resolveMiddlewareSource(file, path, handlerName)
				if middlewareImport != "" {
					pkgDir := filepath.Dir(path)
					result := ExtractAndScoreLogFields(middlewareImport, pkgDir, middlewareFunc)
					if result != nil {
						severity = ScoreSeverity(result.Score)
						description, suggestion = FormatFieldCoverage(handlerName, result)
					}
				}

				findings = append(findings, scanner.Finding{
					RuleID:             "AUDIT-LOG-OK",
					Severity:           severity,
					RequirementID:      "10.2.1",
					FilePath:           path,
					Line:               pos.Line,
					Column:             pos.Column,
					MiddlewareDetected: true,
					Description:        description,
					Suggestion:         suggestion,
				})
				continue // Skip the no-log / unstructured check.
			}

			if hasUnstructured {
				// Unstructured logging: severity based on tier.
				findings = append(findings, scanner.Finding{
					RuleID:        "AUDIT-UNSTRUCTURED",
					Severity:      sev,
					RequirementID: "10.2.1",
					FilePath:      path,
					Line:          pos.Line,
					Column:        pos.Column,
					Description: fmt.Sprintf(
						"Payment handler %s uses unstructured logging (fmt/log package). "+
							"Unstructured logging cannot satisfy PCI DSS 10.2.2 field requirements "+
							"or automated SIEM review (10.4.1.1).",
						handlerName,
					),
					Suggestion: "Replace fmt/log calls with structured logging (slog, zap, zerolog) with required fields per PCI DSS 10.2.1.",
				})
			} else {
				// No logging at all: severity based on tier.
				findings = append(findings, scanner.Finding{
					RuleID:        "AUDIT-NO-LOG",
					Severity:      sev,
					RequirementID: "10.2.1",
					FilePath:      path,
					Line:          pos.Line,
					Column:        pos.Column,
					Description: fmt.Sprintf(
						"No structured audit logging detected in handler body of %s. "+
							"If logging is implemented in middleware, verify it captures required "+
							"PCI DSS 10.2.1 fields: user_id, timestamp, action, outcome, resource. "+
							"Manual verification recommended.",
						handlerName,
					),
					Suggestion: "Add structured logging (slog, zap, zerolog) with required fields per PCI DSS 10.2.1.",
				})
			}
		}
	}

	return findings, lineCount, nil
}

// broadened middleware logging detection.
// 1. router.Use(requestLogger) — ident w/ "log"/"logger" at word boundary
// 2. router.Use(audit.AuditLogger()) — selector with "log"/"logger" substring
// 3. middleware.Install(router) — aggregator follow-through into same-file
// Install/Setup body to detect logger-named wrappers nested inside
//
// Existing patterns (loggingmiddleware, auditmiddleware, requestlogger, arg
// HasPrefix "log") are preserved for backward compatibility.

// aggregatorFuncNames are function names that indicate a middleware aggregator
// whose body we should recursively scan for logger-named args (case 3).
var aggregatorFuncNames = map[string]bool{
	"Install":   true,
	"Setup":     true,
	"Register":  true,
	"Configure": true,
	"Apply":     true,
}

// loggerNameRE matches identifiers containing "log" or "logger" at a word
// boundary (CamelCase or snake_case). Two cases:
//
// 1. Capitalised start of a CamelCase word: `Log`/`Logger` preceded by
// start-of-string or a lowercase letter (e.g. `requestLogger`,
// `AuditLogger`, `RequestLogger`).
// 2. Lowercase standalone: `log`/`logger` preceded by start-of-string or
// underscore and followed by end-of-string, underscore, or an
// uppercase letter (e.g. `log`, `logger`, `access_log`, `logHandler`).
//
// Examples that MATCH:
//
//	log, logger, RequestLogger, requestLogger, AuditLogger, access_log
//
// Examples that do NOT match:
//
//	catalog, dialog, blogs (contain "log" but not at a word boundary),
//	handler, payment
var loggerNameRE = regexp.MustCompile(`(?:^|[a-z_])Log(?:ger)?(?:$|[A-Z_])|(?:^|_)log(?:ger)?(?:$|[_A-Z])`)

// hasLoggingMiddleware checks same-file route registrations for logging middleware
// wrapping the given handler name ( + expansion).
//
// The handlerName parameter is retained for signature compatibility but the
// detection is file-scoped: once any payment handler in the file is covered
// by middleware, the assumption is that the whole router setup uses the same
func hasLoggingMiddleware(file *ast.File, handlerName string) bool {
	_ = handlerName
	if fileHasLoggerArg(file) {
		return true
	}

	// Case 3 (aggregator follow-through): if the file contains a call to any
	// aggregator function (middleware.Install, router.Setup, etc.) AND that
	// aggregator function is defined in the same file AND its body contains
	// a logger-named argument, count it as logging middleware for all payment
	// handlers in the file.
	for _, body := range findAggregatorBodies(file) {
		if blockHasLoggerArg(body) {
			return true
		}
	}
	return false
}

// fileHasLoggerArg returns true if any CallExpr in the file carries a
// logger-named argument (cases 1 and 2).
//
// Matches two shapes of argument:
// 1. `router.Use(requestLogger)` — classic Use/Chain/With* style;
// 2. `mux.Handle("/pay", requestLogger(h))` — wrapper applied inline
// at the route registration call; here the route registration method
// does not carry "Use" in its name, but the logger wrapper is directly
// observable as an argument to the call.
//
// We accept false positives here because FNs (missing a real missing-log
// case) are acceptable while FPs (flagging middleware-covered handlers) are
// the current pain.
func fileHasLoggerArg(file *ast.File) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if argLooksLikeLogger(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// blockHasLoggerArg is the logger-arg check scoped to a single function body.
// Inside aggregator bodies we broaden: any CallExpr whose direct arg matches a
// aggregator pattern uses mux.Handle("/x", wrapperLogger(h)).
func blockHasLoggerArg(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if argLooksLikeLogger(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// argLooksLikeLogger returns true if an argument expression is a function/type
// reference whose name contains "log"/"logger" at a word boundary, OR is a
// call expression whose underlying selector matches. Handles:
//
//	requestLogger (*ast.Ident)
//	audit.AuditLogger (*ast.SelectorExpr)
//	audit.AuditLogger() (*ast.CallExpr wrapping the selector)
//	middleware.LoggingMiddleware (matches legacy list)
func argLooksLikeLogger(arg ast.Expr) bool {
	name := exprToString(arg)
	if name == "" {
		return false
	}
	// Legacy substring list — preserved for backward compatibility.
	lowerName := strings.ToLower(name)
	for _, kw := range loggingMiddlewareKeywords {
		if strings.Contains(lowerName, kw) {
			return true
		}
	}
	// word-boundary log/logger match on the right-most segment of a
	// dotted identifier (e.g. "audit.AuditLogger" -> "AuditLogger").
	parts := strings.Split(name, ".")
	last := parts[len(parts)-1]
	if loggerNameRE.MatchString(last) {
		return true
	}
	// Preserve the legacy HasPrefix("log") heuristic for bare idents like "logReq".
	if strings.HasPrefix(lowerName, "log") {
		return true
	}
	return false
}

// findAggregatorBodies walks the file for calls to aggregator functions
// (middleware.Install / Setup / Register /...) and returns the bodies of
// matching same-file declarations so we can recursively scan them.
func findAggregatorBodies(file *ast.File) []*ast.BlockStmt {
	// Collect local func decls by name.
	localFuncs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		localFuncs[fn.Name.Name] = fn
	}

	var bodies []*ast.BlockStmt
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := exprToString(call.Fun)
		if name == "" {
			return true
		}
		parts := strings.Split(name, ".")
		last := parts[len(parts)-1]
		if !aggregatorFuncNames[last] {
			return true
		}
		// Try same-file declaration first (catches local `func Install(...)` patterns).
		if fn, ok := localFuncs[last]; ok && fn.Body != nil && !seen[last] {
			seen[last] = true
			bodies = append(bodies, fn.Body)
		}
		return true
	})
	return bodies
}

// exprToString extracts a simple string representation of an AST expression.
func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
		return e.Sel.Name
	case *ast.CallExpr:
		return exprToString(e.Fun)
	}
	return ""
}
