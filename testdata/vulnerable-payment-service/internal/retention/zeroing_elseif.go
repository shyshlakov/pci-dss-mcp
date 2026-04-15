package retention

import "net/http"

// HandleZeroingElseIf exercises walkStatements coverage of IfStmt.Else when
// Else is itself an *ast.IfStmt (else-if chain). Z9 fixture for B-11.
func HandleZeroingElseIf(w http.ResponseWriter, r *http.Request) {
	var entry Invoice
	_ = entry.Expiry
	var sensitive [16]byte
	doStep(sensitive[:])
	if r.Method == "POST" {
		w.Write([]byte("posted"))
	} else if r.Method == "PUT" {
		w.Write([]byte("updated"))
		zero(sensitive[:])
	}
}

func doStep(b []byte) {}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
