// Package requests contains transit-only DTOs that move CHD into the Visa
// VTS HTTP client. The CVV / PAN fields are NEVER persisted, so the taint
// bridge must downgrade PAN-KEYWORD to INFO and suppress PAN-TYPE entirely
// per D-06b and the PCI SSC FAQ on non-persistent memory encryption.
package requests

// TokenizeRequest is a request DTO. CVV and PAN flow to service.Tokenize and
// from there straight into an http.Client.Post body — no DB sink reachable.
type TokenizeRequest struct {
	CVV string `json:"cvv"`
	PAN string `json:"pan"`
}
