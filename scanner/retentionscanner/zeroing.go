package retentionscanner

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/analysis"
	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// authorizeKeywords are function name substrings indicating an authorization call.
var authorizeKeywords = []string{
	"authorize",
	"process",
	"charge",
	"verify",
}

// responsePatterns are method names on response writers that indicate sending
// an HTTP response.
var responsePatterns = map[string]bool{
	"Write":       true,
	"WriteHeader": true,
	"JSON":        true,
	"String":      true,
}

// responseCallPatterns are "pkg.Func" patterns for response-writing calls.
var responseCallPatterns = map[string]bool{
	"json.NewEncoder": true,
}

// clearKeywords are function name substrings indicating a memory clear/zero operation.
var clearKeywords = []string{
	"clear",
	"zero",
	"memguard",
	"memset",
	"memclr",
}

// detectZeroingTimingIssues analyzes payment handler functions for incorrect
// ordering of authorize/clear/response operations on sensitive data.
//
// Correct order: authorize -> clear -> response
// Violations:
// - clear before authorize (CRITICAL)
// - defer clear only with no explicit clear (HIGH)
// - clear after response write (HIGH)
func detectZeroingTimingIssues(file *ast.File, fset *token.FileSet, filePath string) []scanner.Finding {
	fw := detector.DetectFramework(file)

	// per-PackageInfo score cache is fresh on each
	// construction -- no global reset required.
	pkgInfo := keywords.PackageInfoFromFile(file, fset, filePath)

	var findings []scanner.Finding

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}

		// Multi-signal payment context gate.
		if !keywords.IsPaymentContext(fn, pkgInfo) {
			continue
		}
		if !detector.IsHTTPHandler(fn, fw) {
			continue
		}

		f := analyzeZeroingInHandler(fn, fset, filePath)
		findings = append(findings, f...)
	}

	return findings
}

// analyzeZeroingInHandler walks a handler function body and tracks positions
// of authorize, clear, and response operations to detect timing issues.
func analyzeZeroingInHandler(fn *ast.FuncDecl, fset *token.FileSet, filePath string) []scanner.Finding {
	var (
		authorizePos  int
		responsePos   int
		clearPos      int
		hasDeferClear bool
	)

	walkStatements(fn.Body.List, fset, &authorizePos, &responsePos, &clearPos, &hasDeferClear)

	var findings []scanner.Finding
	pos := fset.Position(fn.Pos())

	// Case 1: clear before authorize -- CRITICAL.
	if clearPos > 0 && authorizePos > 0 && clearPos < authorizePos {
		findings = append(findings, scanner.Finding{
			RuleID:        "RET-ZERO-BEFORE-AUTH",
			Severity:      scanner.SeverityCritical,
			RequirementID: "3.2.1",
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: "SAD zeroed before authorization call in " + fn.Name.Name +
				" -- authorization may use empty/corrupt data.",
			Suggestion: "Move clear/zero call after authorization.",
		})
		return findings
	}

	// Case 2: defer clear only, no explicit clear -- HIGH.
	if hasDeferClear && clearPos == 0 {
		findings = append(findings, scanner.Finding{
			RuleID:        "RET-ZERO-DEFER-ONLY",
			Severity:      scanner.SeverityHigh,
			RequirementID: "3.2.1",
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: "defer zeroing in " + fn.Name.Name +
				" executes after response -- SAD persists in memory during response transmission.",
			Suggestion: "Add explicit clear/zero call between authorization and response write, not just defer.",
		})
		return findings
	}

	// Case 3: clear after response -- HIGH.
	if clearPos > 0 && responsePos > 0 && clearPos > responsePos {
		findings = append(findings, scanner.Finding{
			RuleID:        "RET-ZERO-AFTER-RESPONSE",
			Severity:      scanner.SeverityHigh,
			RequirementID: "3.2.1",
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: "SAD zeroed after response in " + fn.Name.Name +
				" -- persists during response transmission.",
			Suggestion: "Move clear/zero call before response write.",
		})
		return findings
	}

	// Case 4: correct ordering (authorize < clear < response) -- PASS.
	return findings
}

// walkStatements walks a list of statements in source order to classify
// authorize/response/clear calls and defer-clear intents. Uses ast.Inspect
// for recursion so nested blocks (if/switch/for/select) are handled uniformly
// without duplicating traversal logic per statement type.
func walkStatements(stmts []ast.Stmt, fset *token.FileSet, authorizePos, responsePos, clearPos *int, hasDeferClear *bool) {
	visit := func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.DeferStmt:
			if isDeferClearCall(s) {
				*hasDeferClear = true
			}
			// Don't classify the deferred call as a regular call: a deferred
			// clear/authorize must not be counted as happening here in source
			// order. Skip descent into the DeferStmt subtree.
			return false
		case *ast.RangeStmt:
			if *clearPos == 0 && isRangeZeroClear(s) {
				*clearPos = fset.Position(s.Pos()).Line
			}
		case *ast.CallExpr:
			classifyCall(s, fset, authorizePos, responsePos, clearPos)
		}
		return true
	}
	for _, stmt := range stmts {
		ast.Inspect(stmt, visit)
	}
}

// classifyCall determines whether a call is an authorize, response, or clear call,
// and sets the corresponding position if not already set.
func classifyCall(call *ast.CallExpr, fset *token.FileSet, authorizePos, responsePos, clearPos *int) {
	line := fset.Position(call.Pos()).Line

	name := extractCallName(call)
	if name == "" {
		return
	}

	lower := strings.ToLower(name)

	// Check for authorize call.
	if *authorizePos == 0 {
		for _, kw := range authorizeKeywords {
			if strings.Contains(lower, kw) {
				*authorizePos = line
				return
			}
		}
	}

	// Check for response write call.
	if *responsePos == 0 {
		if isResponseCall(call) {
			*responsePos = line
			return
		}
	}

	// Check for clear/zero call (only on sensitive vars).
	if *clearPos == 0 {
		if isClearCall(call) {
			*clearPos = line
			return
		}
	}
}

// extractCallName returns the function name from a call expression.
// For selector expressions: "obj.Method" or just "Method".
// For plain calls: "funcName".
func extractCallName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// isResponseCall checks if a call writes an HTTP response.
func isResponseCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if responsePatterns[fn.Sel.Name] {
			return true
		}
		// Check "pkg.Func" patterns.
		if x, ok := fn.X.(*ast.Ident); ok {
			fullName := x.Name + "." + fn.Sel.Name
			return responseCallPatterns[fullName]
		}
	}
	return false
}

// isClearCall checks if a call is a memory clear/zero operation with a
// sensitive argument.
func isClearCall(call *ast.CallExpr) bool {
	name := extractCallName(call)
	if name == "" {
		return false
	}

	lower := strings.ToLower(name)
	for _, kw := range clearKeywords {
		if strings.Contains(lower, kw) {
			// Verify at least one argument is sensitive.
			for _, arg := range call.Args {
				if isSensitiveArg(arg) {
					return true
				}
			}
			// Also treat clear calls with sensitive name as matching even without
			// explicit sensitive args (e.g., clearCardData()).
			if analysis.IsSensitiveVarName(name) {
				return true
			}
			// For simplicity, if the call name contains clear keywords,
			// we count it as a clear call -- arguments may be variables
			// whose sensitivity isn't obvious from name alone.
			return true
		}
	}
	return false
}

// isDeferClearCall checks if a defer statement wraps a clear/zero call.
// Handles two shapes: a direct call like `defer clearCard(card)` and an
// immediately invoked function literal like `defer func() { for i:= range card { card[i] = 0 } }()`.
func isDeferClearCall(ds *ast.DeferStmt) bool {
	if isClearCall(ds.Call) {
		return true
	}
	if lit, ok := ds.Call.Fun.(*ast.FuncLit); ok && lit.Body != nil {
		for _, stmt := range lit.Body.List {
			if rng, ok := stmt.(*ast.RangeStmt); ok && isRangeZeroClear(rng) {
				return true
			}
			if expr, ok := stmt.(*ast.ExprStmt); ok {
				if call, ok := expr.X.(*ast.CallExpr); ok && isClearCall(call) {
					return true
				}
			}
		}
	}
	return false
}

// isRangeZeroClear matches `for i:= range v { v[i] = 0 }` where v is a
// sensitive identifier. This idiom is the canonical Go zero-out pattern and
// must be classified as a clear operation alongside explicit clear/memguard
// calls. Mirrors the pattern recognized by panscanner.hasZeroingPattern.
func isRangeZeroClear(rng *ast.RangeStmt) bool {
	target, ok := rng.X.(*ast.Ident)
	if !ok {
		return false
	}
	if !analysis.IsSensitiveVarName(target.Name) {
		return false
	}
	if rng.Body == nil {
		return false
	}
	for _, stmt := range rng.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range assign.Lhs {
			idx, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			ident, ok := idx.X.(*ast.Ident)
			if !ok || ident.Name != target.Name {
				continue
			}
			if i >= len(assign.Rhs) {
				continue
			}
			lit, ok := assign.Rhs[i].(*ast.BasicLit)
			if ok && lit.Value == "0" {
				return true
			}
		}
	}
	return false
}

// isSensitiveArg checks if an argument expression references sensitive data.
func isSensitiveArg(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return analysis.IsSensitiveVarName(e.Name)
	case *ast.SelectorExpr:
		return analysis.IsSensitiveVarName(e.Sel.Name)
	}
	return false
}
