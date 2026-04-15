package delegation

import "net/http"

// DispatchRouter stands in for gin.Engine / echo.Echo / chi.Mux — any
// http.Handler that owns its own middleware chain. Using an interface
// (rather than a stub struct) keeps the file free of FuncDecl nodes so
// that only the Wrapper.ServeHTTP in delegating.go is evaluated by
// authscanner / auditscanner. B-12 fixture support.
type DispatchRouter interface {
	http.Handler
}
