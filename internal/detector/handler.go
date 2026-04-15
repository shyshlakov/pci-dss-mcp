// Package detector provides framework-aware HTTP handler detection for use
// across PCI DSS scanners. It identifies which web framework a Go file uses
// (net/http, gin, echo, chi) and checks whether a function declaration is an
// HTTP handler for that framework.
package detector

import "go/ast"

// Framework represents a recognized Go HTTP framework.
type Framework int

const (
	// FrameworkNetHTTP covers net/http and go-chi/chi.
	FrameworkNetHTTP Framework = iota
	// FrameworkGin covers gin-gonic/gin.
	FrameworkGin
	// FrameworkEcho covers labstack/echo.
	FrameworkEcho
	// FrameworkUnknown is returned when no recognized HTTP framework import is found.
	FrameworkUnknown
)

// DetectFramework inspects the import declarations of a Go file and returns the
// first recognized HTTP framework. Priority: Gin > Echo > net/http/chi > Unknown.
func DetectFramework(file *ast.File) Framework {
	var hasNetHTTP bool

	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		// imp.Path.Value includes surrounding quotes, e.g. "\"net/http\"".
		path := imp.Path.Value
		// Strip quotes.
		if len(path) >= 2 {
			path = path[1 : len(path)-1]
		}

		switch {
		case path == "github.com/gin-gonic/gin":
			return FrameworkGin
		case path == "github.com/labstack/echo" || hasPrefix(path, "github.com/labstack/echo/"):
			return FrameworkEcho
		case path == "net/http" || path == "github.com/go-chi/chi" || hasPrefix(path, "github.com/go-chi/chi/"):
			hasNetHTTP = true
		}
	}

	if hasNetHTTP {
		return FrameworkNetHTTP
	}
	return FrameworkUnknown
}

// IsHTTPHandler returns true if fn has a parameter signature matching the given
// framework's handler convention.
//
// - FrameworkNetHTTP / FrameworkUnknown: has http.ResponseWriter param
// - FrameworkGin: has *gin.Context param
// - FrameworkEcho: has echo.Context param
func IsHTTPHandler(fn *ast.FuncDecl, fw Framework) bool {
	switch fw {
	case FrameworkGin:
		return hasParamType(fn, "*gin.Context")
	case FrameworkEcho:
		return hasParamType(fn, "echo.Context")
	default:
		// FrameworkNetHTTP and FrameworkUnknown both check for ResponseWriter.
		return hasParamType(fn, "http.ResponseWriter")
	}
}

// TypeExprString returns a human-readable string representation of a type
// expression. It handles the common AST node types encountered in function
// parameter lists.
func TypeExprString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + TypeExprString(t.X)
	}
	return ""
}

// hasParamType returns true if fn has at least one parameter whose type string
// matches typeName.
func hasParamType(fn *ast.FuncDecl, typeName string) bool {
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if TypeExprString(field.Type) == typeName {
			return true
		}
	}
	return false
}

// hasPrefix is a simple prefix check to avoid importing strings.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
