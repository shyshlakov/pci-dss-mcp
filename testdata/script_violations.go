package testdata

import (
	"net/http"
)

// VIOLATION: CSP-MISSING - Payment handler with no CSP header (6.4.3)
func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment form"))
}

// VIOLATION: CSP-UNSAFE-INLINE - CSP with unsafe-inline (6.4.3)
func HandleCheckout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
	w.Write([]byte("checkout"))
}

// VIOLATION: CSP-UNSAFE-EVAL - CSP with unsafe-eval (6.4.3)
func ProcessTransaction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-eval'")
	w.Write([]byte("transaction"))
}

// VIOLATION: CSP-NO-SCRIPT-SRC - CSP without script-src or default-src (6.4.3)
func HandleRefund(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "img-src 'self'; font-src 'self'")
	w.Write([]byte("refund"))
}

// NO VIOLATION: CSP with nonce (unsafe-inline ignored per CSP3)
func HandleCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'nonce-abc123' 'unsafe-inline'")
	w.Write([]byte("card"))
}

// NO VIOLATION: CSP set via same-file helper function
func HandleBilling(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Write([]byte("billing"))
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "script-src 'self'")
}

// NO VIOLATION: Not a payment handler (no payment keyword in name)
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
