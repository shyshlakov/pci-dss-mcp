package retention

import "net/http"

// HandleZeroingSwitch exercises walkStatements coverage of SwitchStmt and
// CaseClause bodies. Z10 fixture for B-11.
func HandleZeroingSwitch(w http.ResponseWriter, r *http.Request) {
	var entry Invoice
	_ = entry.Expiry
	var sensitive [16]byte
	primaryStep(sensitive[:])
	switch r.Method {
	case "POST":
		w.Write([]byte("ok"))
		clearBuffer(sensitive[:])
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func primaryStep(b []byte) {}
func clearBuffer(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
