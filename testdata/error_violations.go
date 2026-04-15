package testdata

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// VIOLATION: ERR-01 -- err.Error() in http.Error (CRITICAL)
func HandlePayment(w http.ResponseWriter, r *http.Request) {
	err := processPayment(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError) // VIOLATION: ERR-LEAK-DIRECT
	}
}

// VIOLATION: ERR-01 -- fmt.Fprintf with err (HIGH)
func ProcessCheckout(w http.ResponseWriter, r *http.Request) {
	err := validateCheckout(r)
	if err != nil {
		fmt.Fprintf(w, "checkout error: %v", err) // VIOLATION: ERR-LEAK-FORMAT
	}
}

// VIOLATION: ERR-01 -- w.Write with err.Error() (CRITICAL)
func HandleRefund(w http.ResponseWriter, r *http.Request) {
	dbErr := executeRefund(r)
	if dbErr != nil {
		w.Write([]byte(dbErr.Error())) // VIOLATION: ERR-LEAK-WRITE
	}
}

// VIOLATION: ERR-01 -- json.Encode(err) (CRITICAL)
func ProcessTransaction(w http.ResponseWriter, r *http.Request) {
	err := beginTransaction(r)
	if err != nil {
		json.NewEncoder(w).Encode(err) // VIOLATION: ERR-LEAK-ENCODE
	}
}

// NO VIOLATION -- non-payment handler (ERR-03)
func HandleUser(w http.ResponseWriter, r *http.Request) {
	err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// NO VIOLATION -- static error message
func HandleCardUpdate(w http.ResponseWriter, r *http.Request) {
	err := updateCard(r)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// Helper stubs to make the file compile.
func processPayment(_ *http.Request) error  { return nil }
func validateCheckout(_ *http.Request) error { return nil }
func executeRefund(_ *http.Request) error    { return nil }
func beginTransaction(_ *http.Request) error { return nil }
func getUser(_ *http.Request) error          { return nil }
func updateCard(_ *http.Request) error       { return nil }
