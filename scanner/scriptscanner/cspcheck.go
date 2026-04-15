package scriptscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// scanGoFile parses a single Go source file and checks all payment HTTP handlers
// for CSP header presence and directive weakness.
func (s *ScriptScanner) scanGoFile(path string) ([]scanner.Finding, int, error) {
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

	// Build same-file function map for 1-level delegation resolution.
	fileFuncs := sameFileFuncs(file)

	// per-PackageInfo score cache is fresh on each
	// construction -- no global reset required.
	pkgInfo := keywords.PackageInfoFromFile(file, fset, path)

	var findings []scanner.Finding

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}

		// Multi-signal payment context gate.
		if !keywords.IsPaymentContext(fn, pkgInfo) {
			continue
		}

		// Skip non-HTTP handlers.
		if !detector.IsHTTPHandler(fn, fw) {
			continue
		}

		// Skip functions with no body.
		if fn.Body == nil {
			continue
		}

		findings = append(findings, checkCSPInHandler(fn, file, fset, fw, fileFuncs, path)...)
	}

	return findings, lineCount, nil
}

// checkCSPInHandler checks a single payment handler for CSP header presence
// and directive quality.
func checkCSPInHandler(fn *ast.FuncDecl, file *ast.File, fset *token.FileSet, fw detector.Framework, fileFuncs map[string]*ast.FuncDecl, path string) []scanner.Finding {
	pos := fset.Position(fn.Pos())
	handlerName := fn.Name.Name

	rt := detectResponseType(fn.Body)
	if rt == responseJSON {
		return nil // JSON APIs don't serve HTML, CSP not required.
	}

	// cache S2S callback detection. The suppression ONLY
	// applies later in the unknown-response-type branch — if the handler is
	// known to render HTML, CSP remains mandatory regardless of callback
	// markers (spoofing guard).
	isCallback := isServerToServerCallback(fn, file, path)

	// Step 1: Look for CSP header set in handler body.
	found, cspValue, isLiteral := findCSPHeaderSet(fn.Body)

	// Step 2: If not found, try 1-level same-file delegation.
	if !found {
		found, cspValue, isLiteral = findCSPInDelegates(fn.Body, fileFuncs)
	}

	// Step 3: Generate findings.
	if !found {
		// HTML handlers: HIGH (CSP is required for browser-rendered pages).
		// Unknown handlers: INFO (cannot determine if HTML -- suggest verification).
		severity := scanner.SeverityHigh
		desc := fmt.Sprintf(
			"No Content-Security-Policy header found in payment handler body or same-file helpers of %s. "+
				"PCI DSS 6.4.3 is mandatory since April 1, 2025. "+
				"Verify CSP is set via middleware, reverse proxy, or CDN. "+
				"If not present anywhere -- direct violation of 6.4.3.",
			handlerName,
		)
		if rt == responseUnknown {
			// suppress INFO advisory for server-to-server
			// callback handlers (Mastercard/Visa webhooks, /callback/ routes,
			// callback/ directories). They never render browser HTML so CSP
			// is not applicable. Suppression only fires on the unknown-type
			// branch; responseHTML still reaches the HIGH path below.
			if isCallback {
				return nil
			}
			severity = scanner.SeverityInfo
			desc = fmt.Sprintf(
				"Could not determine response type for payment handler %s -- "+
					"verify CSP if this serves HTML. PCI DSS 6.4.3 requires CSP for browser-rendered pages.",
				handlerName,
			)
		}
		return []scanner.Finding{{
			RuleID:        "CSP-MISSING",
			Severity:      severity,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description:   desc,
			Suggestion:    "Add Content-Security-Policy header in handler or middleware. Minimal policy: script-src 'self'",
		}}
	}

	// CSP found but value is not a string literal.
	if !isLiteral {
		return []scanner.Finding{{
			RuleID:        "CSP-VALUE-UNANALYZABLE",
			Severity:      scanner.SeverityInfo,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf(
				"CSP header set in %s but value is not a string literal -- cannot analyze directives statically. Manual review recommended.",
				handlerName,
			),
			Suggestion: "Consider using a string literal for CSP value to enable static analysis.",
		}}
	}

	// Analyze CSP value.
	analysis := parseCSP(cspValue)
	var findings []scanner.Finding

	if analysis.HasUnsafeInline {
		findings = append(findings, scanner.Finding{
			RuleID:        "CSP-UNSAFE-INLINE",
			Severity:      scanner.SeverityHigh,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf(
				"'unsafe-inline' in CSP script-src of %s allows inline script execution, undermining XSS protection required by PCI DSS 6.4.3.",
				handlerName,
			),
			Suggestion: "Remove 'unsafe-inline' from CSP. Use nonces or hashes for inline scripts instead.",
		})
	}

	if analysis.HasUnsafeEval {
		findings = append(findings, scanner.Finding{
			RuleID:        "CSP-UNSAFE-EVAL",
			Severity:      scanner.SeverityHigh,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf(
				"'unsafe-eval' in CSP script-src of %s allows eval() execution, undermining script integrity required by PCI DSS 6.4.3.",
				handlerName,
			),
			Suggestion: "Remove 'unsafe-eval' from CSP. Refactor JavaScript to avoid eval(), new Function(), and similar constructs.",
		})
	}

	if analysis.NoScriptRestriction {
		findings = append(findings, scanner.Finding{
			RuleID:        "CSP-NO-SCRIPT-SRC",
			Severity:      scanner.SeverityHigh,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf(
				"CSP header present in %s but contains no script-src or default-src directive -- no script source restriction.",
				handlerName,
			),
			Suggestion: "Add script-src directive to CSP. Minimal policy: script-src 'self'",
		})
	}

	// Valid CSP (no issues found): INFO.
	if !analysis.HasUnsafeInline && !analysis.HasUnsafeEval && !analysis.NoScriptRestriction {
		findings = append(findings, scanner.Finding{
			RuleID:        "CSP-OK",
			Severity:      scanner.SeverityInfo,
			RequirementID: "6.4.3",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf(
				"CSP header found in %s. Note: CSP alone does NOT satisfy full 6.4.3 -- "+
					"also required: SRI hashes on external scripts (see SCRIPT-03), "+
					"script inventory documentation (manual verification required). "+
					"CSP is necessary but not sufficient for 6.4.3 compliance.",
				handlerName,
			),
			Suggestion: "Verify SRI attributes on external scripts and maintain a script inventory per PCI DSS 6.4.3.",
		})
	}

	return findings
}

// findCSPHeaderSet walks a function body looking for calls that set the
// Content-Security-Policy header. It checks for common patterns across
// net/http, gin, and echo frameworks.
//
// Returns: found (CSP header call detected), cspValue (the CSP string value),
// isLiteral (whether the value was a string literal we can parse).
func findCSPHeaderSet(body *ast.BlockStmt) (found bool, cspValue string, isLiteral bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Find the argument index where "Content-Security-Policy" appears.
		cspArgIdx := -1
		for i, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			if strings.EqualFold(val, "Content-Security-Policy") {
				cspArgIdx = i
				break
			}
		}

		if cspArgIdx < 0 {
			return true
		}

		// CSP header name found. Extract the value from the next argument.
		found = true
		valueIdx := cspArgIdx + 1
		if valueIdx >= len(call.Args) {
			// No value argument present.
			isLiteral = false
			return false
		}

		valueLit, ok := call.Args[valueIdx].(*ast.BasicLit)
		if !ok || valueLit.Kind != token.STRING {
			// Value is not a string literal (variable reference, etc.).
			isLiteral = false
			return false
		}

		val, err := strconv.Unquote(valueLit.Value)
		if err != nil {
			isLiteral = false
			return false
		}

		cspValue = val
		isLiteral = true
		return false
	})

	return found, cspValue, isLiteral
}

// sameFileFuncs builds a map of all top-level function declarations in a file
// indexed by function name. Used for 1-level same-file call resolution.
func sameFileFuncs(file *ast.File) map[string]*ast.FuncDecl {
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		// Only include package-level functions (not methods).
		if fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}
	return funcs
}

// findCSPInDelegates walks a function body looking for plain function calls
// (no package prefix), looks up each in fileFuncs, and checks if any delegate
// function sets a CSP header. Returns the first match.
func findCSPInDelegates(body *ast.BlockStmt, fileFuncs map[string]*ast.FuncDecl) (bool, string, bool) {
	var resultFound bool
	var resultValue string
	var resultLiteral bool

	ast.Inspect(body, func(n ast.Node) bool {
		if resultFound {
			return false
		}

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Only plain function calls (no selector).
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}

		// Look up the function in same-file functions.
		fn, exists := fileFuncs[ident.Name]
		if !exists || fn.Body == nil {
			return true
		}

		found, value, isLiteral := findCSPHeaderSet(fn.Body)
		if found {
			resultFound = true
			resultValue = value
			resultLiteral = isLiteral
			return false
		}

		return true
	})

	return resultFound, resultValue, resultLiteral
}
