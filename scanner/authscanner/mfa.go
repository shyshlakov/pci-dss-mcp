package authscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// mfaKeywords are substrings that indicate MFA enforcement in function/method names.
// Matching is case-insensitive.
var mfaKeywords = []string{
	"mfa",
	"totp",
	"2fa",
	"two_factor",
	"twofactor",
	"otp",
	"multi_factor",
	"multifactor",
}

// containsMFAKeyword returns true if the lowercased name contains any MFA keyword.
func containsMFAKeyword(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range mfaKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// routeRegistrationMethods are selector names that indicate HTTP route registration.
var routeRegistrationMethods = map[string]bool{
	"HandleFunc": true,
	"Handle":     true,
	"Get":        true,
	"Post":       true,
	"Put":        true,
	"Delete":     true,
	"Patch":      true,
	"GET":        true,
	"POST":       true,
	"PUT":        true,
	"DELETE":     true,
	"PATCH":      true,
	"Group":      true,
	"Route":      true,
}

// detectMissingMFA detects payment routes/handlers missing MFA middleware.
// Uses a hybrid approach:
// - Strategy A: Route registration detection (http.HandleFunc, mux.HandleFunc, router methods)
// - Strategy B: Payment handler function detection (payment name + ResponseWriter + no MFA in body)
func detectMissingMFA(file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	var findings []scanner.Finding

	// Track handler function names seen in any payment route registration (Strategy A),
	// so Strategy B does not create duplicate findings for the same handler.
	// This includes both flagged handlers (no MFA) and protected handlers (has MFA).
	routeRegisteredHandlers := make(map[string]bool)

	// per-PackageInfo score cache is fresh on each
	// construction -- no global reset required.
	pkgInfo := keywords.PackageInfoFromFile(file, fset, path)

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			// Strategy A: Route registration detection.
			finding, handlerName := checkRouteRegistration(node, fset, path)
			if handlerName != "" {
				routeRegisteredHandlers[handlerName] = true
			}
			if finding != nil {
				findings = append(findings, *finding)
			}

		case *ast.FuncDecl:
			// Strategy B: Payment handler function detection.
			if f := checkPaymentHandler(node, fset, path, pkgInfo, routeRegisteredHandlers); f != nil {
				findings = append(findings, *f)
			}
		}
		return true
	})

	return findings
}

// checkRouteRegistration checks if a CallExpr is a route registration for a payment path
// without an MFA middleware wrapper. Returns a finding (nil if clean or not a route registration)
// and the handler function name (empty if not identifiable).
func checkRouteRegistration(call *ast.CallExpr, fset *token.FileSet, filePath string) (*scanner.Finding, string) {
	// Must be a selector call (e.g., http.HandleFunc, mux.HandleFunc, router.GET).
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, ""
	}

	if !routeRegistrationMethods[sel.Sel.Name] {
		return nil, ""
	}

	// Need at least 2 args: path and handler.
	if len(call.Args) < 2 {
		return nil, ""
	}

	// First arg must be a string literal (route path).
	routePath := extractStringLiteral(call.Args[0])
	if routePath == "" {
		return nil, ""
	}

	// Check if this is a payment path.
	if !keywords.IsPaymentPath(routePath) {
		return nil, ""
	}

	// Extract handler name for dedup tracking regardless of MFA status.
	handlerName := extractHandlerIdent(call.Args[1])

	// Check handler argument (second arg) for MFA wrapper.
	handlerArg := call.Args[1]
	if hasMFAWrapper(handlerArg) {
		return nil, handlerName
	}

	pos := fset.Position(call.Pos())
	// Severity stays HIGH per PCI DSS 8.4.2 -- no permanent downgrade.
	// Static analysis cannot confirm infrastructure-level MFA.
	return &scanner.Finding{
		RuleID:        "AUTH-MISSING-MFA",
		Severity:      scanner.SeverityHigh,
		RequirementID: "8.4.2",
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description:   fmt.Sprintf("No MFA middleware detected on payment route %s. Verify MFA is enforced at application or infrastructure level (API gateway, reverse proxy, service mesh).", routePath),
		Suggestion:    "Wrap payment route handler with MFA middleware (e.g., mfaRequired(handler)) or verify MFA enforcement at infrastructure level.",
	}, handlerName
}

// checkPaymentHandler checks if a FuncDecl is a payment HTTP handler without MFA enforcement.
func checkPaymentHandler(fn *ast.FuncDecl, fset *token.FileSet, filePath string, pkgInfo *keywords.PackageInfo, flaggedRouteHandlers map[string]bool) *scanner.Finding {
	if fn.Name == nil {
		return nil
	}

	// Step 1: multi-signal payment context gate.
	if !keywords.IsPaymentContext(fn, pkgInfo) {
		return nil
	}

	// Must be an HTTP handler (has http.ResponseWriter parameter).
	if !detector.IsHTTPHandler(fn, detector.FrameworkNetHTTP) {
		return nil
	}

	// skip delegation-only wrappers. Their MFA enforcement lives on
	// the embedded router's middleware chain, which is analyzed separately
	// via Strategy A (route registration detection) when the child routes
	// are declared.
	if isDelegationOnlyHandler(fn.Body) {
		return nil
	}

	// Check if already flagged by route registration detection.
	if flaggedRouteHandlers[fn.Name.Name] {
		return nil
	}

	// Check function body for MFA-related calls.
	if fn.Body != nil && bodyContainsMFACall(fn.Body) {
		return nil
	}

	pos := fset.Position(fn.Pos())
	// Severity stays HIGH per PCI DSS 8.4.2 -- no permanent downgrade.
	// Static analysis cannot confirm infrastructure-level MFA.
	return &scanner.Finding{
		RuleID:        "AUTH-MISSING-MFA",
		Severity:      scanner.SeverityHigh,
		RequirementID: "8.4.2",
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description:   fmt.Sprintf("No MFA middleware detected on payment handler %s. Verify MFA is enforced at application or infrastructure level (API gateway, reverse proxy, service mesh).", fn.Name.Name),
		Suggestion:    "Wrap payment route handler with MFA middleware (e.g., mfaRequired(handler)) or verify MFA enforcement at infrastructure level.",
	}
}

// hasMFAWrapper checks if the handler argument is wrapped in an MFA-related call.
// E.g., mfaMiddleware(handlePayment) -- the outer call name contains an MFA keyword.
func hasMFAWrapper(expr ast.Expr) bool {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	name := callExprFuncName(call)
	return containsMFAKeyword(name)
}

// bodyContainsMFACall walks a function body looking for any call whose name
// contains an MFA keyword.
func bodyContainsMFACall(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callExprFuncName(call)
		if containsMFAKeyword(name) {
			found = true
			return false
		}
		return true
	})
	return found
}

// extractHandlerIdent extracts the handler function name from a handler argument expression.
// For plain ident handlers (e.g., handlePayment), returns the name.
// For wrapped calls (e.g., mfaMiddleware(handlePayment)), returns the inner handler name.
func extractHandlerIdent(expr ast.Expr) string {
	switch h := expr.(type) {
	case *ast.Ident:
		return h.Name
	case *ast.SelectorExpr:
		return h.Sel.Name
	case *ast.CallExpr:
		// Wrapped handler: mfaMiddleware(handlePayment) -- extract inner arg.
		if len(h.Args) > 0 {
			return extractHandlerIdent(h.Args[0])
		}
	}
	return ""
}

// callExprFuncName extracts the function name from a CallExpr's Fun field.
// Handles *ast.Ident (plain function) and *ast.SelectorExpr (pkg.Method).
func callExprFuncName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
		return fn.Sel.Name
	}
	return ""
}

// isDelegationOnlyHandler reports whether body is a single delegation call
// that forwards to another http.Handler. These wrappers are router plumbing
// and their MFA enforcement lives on the embedded router's middleware
// chain, which is analyzed separately. Skipping them here prevents false
//
// Shapes recognized (all must be the sole statement in body.List):
//
//	x.ServeHTTP(w, r) // direct field/receiver delegation
//	x.y.ServeHTTP(w, r) // nested selector (h.r.ServeHTTP)
//	x.ServeHTTPC(ctx, w, r) // context-aware variant
//	x.Handler.ServeHTTP(w, r) // embedded-handler pattern
//	x.HandleContext(c) // gin-specific dispatch
func isDelegationOnlyHandler(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	exprStmt, ok := body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := exprStmt.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	case "ServeHTTP", "ServeHTTPC", "HandleContext":
		return selectorRootIsIdent(sel.X)
	}
	return false
}

// selectorRootIsIdent walks a selector expression chain until the leftmost
// operand and reports whether it terminates in an identifier. Covers
// x.ServeHTTP, x.y.ServeHTTP, x.y.z.ServeHTTP without admitting function
// calls or literal expressions as the delegation root.
func selectorRootIsIdent(expr ast.Expr) bool {
	for {
		switch e := expr.(type) {
		case *ast.Ident:
			return true
		case *ast.SelectorExpr:
			expr = e.X
		default:
			return false
		}
	}
}

// extractStringLiteral extracts the unquoted value from a string BasicLit.
// Returns empty string if the expression is not a string literal.
func extractStringLiteral(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	// Remove surrounding quotes.
	s := lit.Value
	if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
		return s[1 : len(s)-1]
	}
	return s
}
