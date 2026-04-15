//go:build ignore

// Package normaltest is a fixture: regular payment handler OUTSIDE any
// callback context. It must STILL emit CSP-MISSING at INFO severity when
// response type is unknown (no regression from FP3-06 fix).
package normaltest

import "net/http"

// HandlePayment has no JSON/HTML indicators and lives in a non-callback
// directory. Expected: CSP-MISSING at INFO severity.
func HandlePayment(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("payment"))
}
