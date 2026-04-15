package retention

import "net/http"

// HandleZeroingTypeSwitch exercises walkStatements coverage of
// TypeSwitchStmt and its case bodies. Z11 fixture for B-11.
func HandleZeroingTypeSwitch(w http.ResponseWriter, r *http.Request) {
	var entry Invoice
	_ = entry.Expiry
	var sensitive [16]byte
	runStep(sensitive[:])
	var ctx interface{} = r.Context()
	switch ctx.(type) {
	case interface{ Value(any) any }:
		w.Write([]byte("ctx"))
		zeroBuffer(sensitive[:])
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func runStep(b []byte) {}
func zeroBuffer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
