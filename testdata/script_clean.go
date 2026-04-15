package testdata

import "net/http"

func HandlePaymentClean(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	w.Write([]byte("payment"))
}

func HandleCheckoutClean(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'nonce-random123'")
	w.Write([]byte("checkout"))
}
