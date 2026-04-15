//go:build ignore

// Package callbacktest is a fixture: S2S card-network webhook handler with
// unknown response type. It must NOT emit CSP-MISSING (FP3-06, D-21).
package callbacktest

import "net/http"

// HandlePaymentNotify is a payment handler whose response type is not
// statically determinable (no json.Encode, no template.Execute, no
// Content-Type header). Because the source file lives under a callback/
// directory, the scanner must suppress the CSP-MISSING INFO advisory.
func HandlePaymentNotify(w http.ResponseWriter, r *http.Request) {
	// Simulated webhook acknowledgment -- no HTML, no JSON indicators.
	_, _ = w.Write([]byte("ok"))
}
