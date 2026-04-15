package retention

import (
	"net/http"
	"time"
)

// HandleZeroingSelect exercises walkStatements coverage of SelectStmt and
// CommClause bodies. Z12 fixture for B-11.
func HandleZeroingSelect(w http.ResponseWriter, r *http.Request) {
	var entry Invoice
	_ = entry.Expiry
	var sensitive [16]byte
	initStep(sensitive[:])
	done := make(chan struct{}, 1)
	done <- struct{}{}
	select {
	case <-done:
		w.Write([]byte("done"))
		clearNow(sensitive[:])
	case <-time.After(time.Second):
		w.WriteHeader(http.StatusRequestTimeout)
	}
}

func initStep(b []byte) {}
func clearNow(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
