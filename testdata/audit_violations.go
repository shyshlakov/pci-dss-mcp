package testdata

import (
	"fmt"
	"log/slog"
	"net/http"
)

// HandlePaymentNoLog is a payment handler with no logging at all.
// VIOLATION: AUDIT-NO-LOG - No audit logging in payment handler (10.2.1)
func HandlePaymentNoLog(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment processed"))
}

// HandleCheckoutFmtOnly is a payment handler with only unstructured logging.
// VIOLATION: AUDIT-UNSTRUCTURED - Unstructured logging in payment handler (10.2.1)
func HandleCheckoutFmtOnly(w http.ResponseWriter, r *http.Request) {
	fmt.Println("processing checkout")
	w.Write([]byte("checkout done"))
}

// HandleTransactionWithSlog is a payment handler with structured logging.
// No violation -- structured logging present.
func HandleTransactionWithSlog(w http.ResponseWriter, r *http.Request) {
	slog.Info("transaction processed", "user_id", "123", "amount", 100)
	w.Write([]byte("ok"))
}

// HandleRefundDelegated has no direct logging but calls a helper that logs.
// No violation -- 1-level same-file call resolution.
func HandleRefundDelegated(w http.ResponseWriter, r *http.Request) {
	processRefund()
	w.Write([]byte("refund ok"))
}

func processRefund() {
	slog.Info("refund processed")
}

// HandleUserProfile is NOT a payment handler -- should not be checked.
func HandleUserProfile(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("user profile"))
}
