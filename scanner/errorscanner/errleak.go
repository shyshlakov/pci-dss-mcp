package errorscanner

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const (
	errLeakSuggestion = "Return a generic error message to the client and log the detailed error server-side."
	requirementID     = "6.2.4"
)

// DetectErrorLeaksInBody walks a function body's AST and detects four patterns
// of error information leaking into HTTP responses:
//
// 1. http.Error(w, err.Error(), code) -- ERR-LEAK-DIRECT (CRITICAL)
// 2. fmt.Fprintf(w, format,..., err) -- ERR-LEAK-FORMAT (HIGH)
// 3. w.Write([]byte(err.Error())) -- ERR-LEAK-WRITE (CRITICAL)
// 4. json.NewEncoder(w).Encode(err) -- ERR-LEAK-ENCODE (CRITICAL)
func DetectErrorLeaksInBody(body *ast.BlockStmt, fset *token.FileSet, filePath string) []scanner.Finding {
	if body == nil {
		return nil
	}

	var findings []scanner.Finding

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if f := checkHTTPError(call, fset, filePath); f != nil {
			findings = append(findings, *f)
		}
		if f := checkFmtFprintf(call, fset, filePath); f != nil {
			findings = append(findings, *f)
		}
		if f := checkWriteBytes(call, fset, filePath); f != nil {
			findings = append(findings, *f)
		}
		if f := checkJSONEncode(call, fset, filePath); f != nil {
			findings = append(findings, *f)
		}

		return true
	})

	return findings
}

// checkHTTPError detects Pattern 1: http.Error(w, errExpr, code).
// The second argument (index 1) must contain an error reference.
func checkHTTPError(call *ast.CallExpr, fset *token.FileSet, filePath string) *scanner.Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "http" || sel.Sel.Name != "Error" {
		return nil
	}
	if len(call.Args) < 2 {
		return nil
	}

	// Second argument is the error message string.
	if !containsErrReference(call.Args[1]) {
		return nil
	}

	pos := fset.Position(call.Pos())
	return &scanner.Finding{
		RuleID:        "ERR-LEAK-DIRECT",
		Severity:      scanner.SeverityCritical,
		RequirementID: requirementID,
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description:   "Internal error details passed to http.Error() in payment handler",
		Suggestion:    errLeakSuggestion,
	}
}

// checkFmtFprintf detects Pattern 2: fmt.Fprintf(w, format,..., err).
// Any argument after the writer and format string that contains an error reference.
func checkFmtFprintf(call *ast.CallExpr, fset *token.FileSet, filePath string) *scanner.Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "fmt" || sel.Sel.Name != "Fprintf" {
		return nil
	}
	// fmt.Fprintf(w, format, args...) -- need at least 3 args.
	if len(call.Args) < 3 {
		return nil
	}

	// Check args from index 2 onward for error references.
	for _, arg := range call.Args[2:] {
		if containsErrReference(arg) {
			pos := fset.Position(call.Pos())
			return &scanner.Finding{
				RuleID:        "ERR-LEAK-FORMAT",
				Severity:      scanner.SeverityHigh,
				RequirementID: requirementID,
				FilePath:      filePath,
				Line:          pos.Line,
				Column:        pos.Column,
				Description:   "Error variable passed to fmt.Fprintf() writing to response in payment handler",
				Suggestion:    errLeakSuggestion,
			}
		}
	}
	return nil
}

// checkWriteBytes detects Pattern 3: w.Write([]byte(err.Error())).
// Matches any.Write() call where the argument contains err.Error().
func checkWriteBytes(call *ast.CallExpr, fset *token.FileSet, filePath string) *scanner.Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Write" {
		return nil
	}
	// The receiver should be an identifier (the writer variable).
	if _, ok := sel.X.(*ast.Ident); !ok {
		return nil
	}
	if len(call.Args) < 1 {
		return nil
	}

	// Check if any argument contains an error reference (possibly inside []byte conversion).
	if containsErrReference(call.Args[0]) {
		pos := fset.Position(call.Pos())
		return &scanner.Finding{
			RuleID:        "ERR-LEAK-WRITE",
			Severity:      scanner.SeverityCritical,
			RequirementID: requirementID,
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description:   "Error details written via w.Write() in payment handler",
			Suggestion:    errLeakSuggestion,
		}
	}
	return nil
}

// checkJSONEncode detects Pattern 4: json.NewEncoder(w).Encode(err).
// The Fun is a SelectorExpr with Sel.Name == "Encode" and X is a CallExpr
// matching "json.NewEncoder", and the Encode argument is an error-like ident.
func checkJSONEncode(call *ast.CallExpr, fset *token.FileSet, filePath string) *scanner.Finding {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Encode" {
		return nil
	}

	// X should be a CallExpr for json.NewEncoder(w).
	innerCall, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return nil
	}
	innerSel, ok := innerCall.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	pkgIdent, ok := innerSel.X.(*ast.Ident)
	if !ok || pkgIdent.Name != "json" || innerSel.Sel.Name != "NewEncoder" {
		return nil
	}

	// Check if the Encode argument is an error-like identifier.
	if len(call.Args) < 1 {
		return nil
	}
	if containsErrReference(call.Args[0]) {
		pos := fset.Position(call.Pos())
		return &scanner.Finding{
			RuleID:        "ERR-LEAK-ENCODE",
			Severity:      scanner.SeverityCritical,
			RequirementID: requirementID,
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description:   "Error encoded as JSON via json.NewEncoder().Encode() in payment handler",
			Suggestion:    errLeakSuggestion,
		}
	}
	return nil
}

// containsErrReference recursively checks if an expression references an error
// variable. Catches err, dbErr, parseError, httpErr, etc. per research Pitfall 3.
func containsErrReference(expr ast.Expr) bool {
	if expr == nil {
		return false
	}

	switch e := expr.(type) {
	case *ast.Ident:
		// Variable name contains "err" (case-insensitive).
		return isErrIdent(e.Name)

	case *ast.SelectorExpr:
		//.Error() method selector -- the receiver is likely an error variable.
		if e.Sel.Name == "Error" {
			return true
		}
		return containsErrReference(e.X)

	case *ast.CallExpr:
		// err.Error() call or fmt.Sprintf with error args.
		if containsErrReference(e.Fun) {
			return true
		}
		for _, arg := range e.Args {
			if containsErrReference(arg) {
				return true
			}
		}

	case *ast.UnaryExpr:
		return containsErrReference(e.X)

	case *ast.ParenExpr:
		return containsErrReference(e.X)

	case *ast.IndexExpr:
		return containsErrReference(e.X)

	case *ast.SliceExpr:
		return containsErrReference(e.X)

	case *ast.CompositeLit:
		// map/struct/array literal — e.g., map[string]any{"error": err}.
		// Recurse into each element so ERR-LEAK-ENCODE fires on error
		// references carried inside response body composite literals.
		for _, elt := range e.Elts {
			if containsErrReference(elt) {
				return true
			}
		}

	case *ast.KeyValueExpr:
		// Map/struct key-value entry — the value is the payload, the key is
		// label-only and is not an error reference by itself.
		return containsErrReference(e.Value)
	}

	return false
}

// isErrIdent returns true if the identifier name contains "err" (case-insensitive).
// This catches: err, dbErr, parseError, httpErr, valErr, etc.
func isErrIdent(name string) bool {
	return strings.Contains(strings.ToLower(name), "err")
}
