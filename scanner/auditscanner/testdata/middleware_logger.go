//go:build ignore

package middleware_logger

import (
	"net/http"

	"example.com/audit"
)

// Pattern 1: named function ending in Logger
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

// Pattern 2: aggregator that installs several middlewares including a logger
func installMiddleware(mux *http.ServeMux) {
	mux.Handle("/pay", requestLogger(http.HandlerFunc(PaymentHandler)))
}

// PaymentHandler — no inline logging, should NOT be flagged once middleware detection broadened.
func PaymentHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Pattern 3: selector + call form (audit.AuditLogger())
func setupRouter(mux *http.ServeMux) {
	mux.Handle("/checkout",
		audit.AuditLogger()(http.HandlerFunc(CheckoutHandler)),
	)
}

func CheckoutHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Pattern 4: aggregator middleware.Install(...) follow-through.
// Aggregator function body contains inline mux.Handle calls with a
// logger-named wrapper.
func Install(mux *http.ServeMux) {
	mux.Handle("/refund",
		requestLogger(http.HandlerFunc(RefundHandler)),
	)
}

// Aggregator call site:
func Route(mux *http.ServeMux) {
	Install(mux)
}

func RefundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// Negative case — handler with NO middleware wrapper anywhere, should STILL be flagged.
func NoMiddlewarePayHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
