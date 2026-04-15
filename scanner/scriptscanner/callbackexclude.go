package scriptscanner

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// isServerToServerCallback returns true when the handler is a server-to-server
// webhook callback that never renders HTML in a browser. CSP is not applicable
// to these handlers.
//
// A handler qualifies if ANY of:
// 1. Its function name ends with "Callback" (case-insensitive).
// 2. It is registered on a route path containing "/callback/" (case-insensitive).
// 3. Its source file lives inside a "callback" (or "callbacks") directory segment.
func isServerToServerCallback(fn *ast.FuncDecl, file *ast.File, path string) bool {
	if fn == nil || fn.Name == nil {
		return false
	}
	lowerName := strings.ToLower(fn.Name.Name)

	// Check 1: function name suffix.
	if strings.HasSuffix(lowerName, "callback") {
		return true
	}

	// Check 3: source file within a callback/ directory segment.
	if pathInCallbackDir(path) {
		return true
	}

	// Check 2: handler registered on a callback route path.
	if handlerRegisteredOnCallbackRoute(file, fn.Name.Name) {
		return true
	}

	return false
}

// pathInCallbackDir returns true if any path segment equals "callback" or
// "callbacks" (case-insensitive).
func pathInCallbackDir(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, seg := range strings.Split(lower, "/") {
		if seg == "callback" || seg == "callbacks" {
			return true
		}
	}
	return false
}

// handlerRegisteredOnCallbackRoute walks the file AST looking for any
// CallExpr whose argument list contains BOTH:
// - a string literal containing "/callback/" (case-insensitive), and
// - an *ast.Ident referencing handlerName OR an *ast.SelectorExpr ending
// in handlerName (e.g., h.Process or pkg.Handler).
//
// This catches common router registration patterns:
//
//	router.POST("/callback/mastercard", MastercardHandler)
//	mux.HandleFunc("/callback/visa", visa.Handle)
//	e.POST("/callback/:provider", h.Process)
func handlerRegisteredOnCallbackRoute(file *ast.File, handlerName string) bool {
	if file == nil || handlerName == "" {
		return false
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var hasCallbackLiteral bool
		var mentionsHandler bool
		for _, arg := range call.Args {
			switch a := arg.(type) {
			case *ast.BasicLit:
				if a.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(a.Value)
				if err != nil {
					continue
				}
				if strings.Contains(strings.ToLower(val), "/callback/") {
					hasCallbackLiteral = true
				}
			case *ast.Ident:
				if a.Name == handlerName {
					mentionsHandler = true
				}
			case *ast.SelectorExpr:
				if a.Sel != nil && a.Sel.Name == handlerName {
					mentionsHandler = true
				}
			}
		}
		if hasCallbackLiteral && mentionsHandler {
			found = true
			return false
		}
		return true
	})
	return found
}
