package requests

// TokenizeRequest is a request DTO — the CVV / PAN fields are TRANSIT data
// that flow to the Visa VTS HTTP client and are never stored in any
// database. The taint engine must confirm this and the PAN-KEYWORD / PAN-TYPE
// scanners can then suppress their findings on these fields.
type TokenizeRequest struct {
	CVV string `json:"cvv"`
	PAN string `json:"pan"`
}
