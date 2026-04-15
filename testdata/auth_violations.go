package testdata

import (
	"fmt"
	"net/http"
	"os"
)

// --- AUTH-01: Hardcoded Passwords ---

var dbPassword = "supersecret123" // VIOLATION: AUTH-HARDCODED-PWD - hardcoded password (8.3.1)

const defaultPasswd = "admin" // VIOLATION: AUTH-HARDCODED-PWD - hardcoded password (8.3.1)

func initConfig() {
	pass := "bootstrap-pass" // VIOLATION: AUTH-HARDCODED-PWD - hardcoded password (8.3.1)
	_ = pass
	os.Setenv("DB_PASSWORD", "prod-secret") // VIOLATION: AUTH-HARDCODED-PWD - os.Setenv hardcoded (8.3.1)
	os.Setenv("API_KEY", "sk-live-12345")   // VIOLATION: AUTH-HARDCODED-PWD - os.Setenv hardcoded (8.3.1)
}

var placeholderPwd = "changeme" // INFO: placeholder password

// --- AUTH-02: Weak Password Policy ---

func validatePassword(password string) error {
	if len(password) < 8 { // VIOLATION: AUTH-WEAK-POLICY - threshold 8 < 12 (8.3.6)
		return fmt.Errorf("password too short")
		// Also: VIOLATION: AUTH-BYTE-COUNT - len() counts bytes (8.3.6)
	}
	return nil
}

// --- AUTH-03: Missing MFA on Payment Routes ---

func handlePaymentAuth(w http.ResponseWriter, r *http.Request) { // VIOLATION: AUTH-MISSING-MFA - payment handler without MFA (8.4.2)
	fmt.Fprintf(w, "payment processed")
}

func registerRoutes() {
	http.HandleFunc("/checkout", handleCheckoutAuth) // VIOLATION: AUTH-MISSING-MFA - payment route without MFA (8.4.2)
}

func handleCheckoutAuth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "checkout page")
}

// --- Clean patterns (should NOT be flagged) ---

func handleUserProfile(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "user profile") // Not a payment handler
}

func processPaymentData(data []byte) {
	// Not an HTTP handler (no ResponseWriter), should NOT be flagged for MFA
	_ = data
}

func handleSecurePayment(w http.ResponseWriter, r *http.Request) {
	requireMFA(r) // Has MFA check in body -- should NOT be flagged
	fmt.Fprintf(w, "secure payment")
}

// Stubs to keep the file compilable.
func requireMFA(_ *http.Request) {}
