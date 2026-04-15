// Package errorscanner implements the error handling scanner that detects
// payment handlers leaking internal error details to HTTP responses.
//
// Detection scope: Payment-context handler functions only, identified via
// the multi-signal scorer in internal/keywords (IsPaymentContext) plus
// http.ResponseWriter parameter presence (HasResponseWriterParam).
//
// This scanner addresses PCI DSS 6.2.4 -- payment handlers must not expose
// internal error messages that could reveal system internals to attackers.
package errorscanner

import (
	"go/ast"

	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
)

// HasResponseWriterParam returns true if the given FuncDecl has a parameter
// whose type is http.ResponseWriter. This confirms the function is an HTTP
// handler that can write response bodies.
// Delegates to the shared detector package for framework-aware checking.
func HasResponseWriterParam(fn *ast.FuncDecl) bool {
	return detector.IsHTTPHandler(fn, detector.FrameworkNetHTTP)
}
