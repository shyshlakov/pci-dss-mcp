// Package testdata contains test fixtures for PCI DSS compliance scanning.
// all_violations.go: Comprehensive fixture that triggers every Go-based scanner rule.
// Used by TestAllViolationsFixture for regression safety after an earlier release changes.
// Each section is labeled with the rule ID it triggers.
//
// DO NOT use as example code. These are INTENTIONAL violations.
package testdata

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"
)

// =============================================================================
// PAN Scanner rules
// =============================================================================

// --- PAN-KEYWORD: struct field with sensitive name ---
// --- PAN-TYPE: CardNumber declared as string instead of []byte ---
type AllViolationsPayment struct {
	CardNumber string  // triggers PAN-KEYWORD (struct field) + PAN-TYPE (string type)
	CVV        string  // triggers PAN-KEYWORD + PAN-TYPE
	Amount     float64 // payment context indicator
	Currency   string  // payment context indicator
	Merchant   string  // payment context indicator
}

// --- PAN-LITERAL: Luhn-valid card number in string literal ---
var allViolationsTestCard = "4532015112830366" // Visa test number

// --- PAN-LOGGER: sensitive variable passed to logger ---
func allViolationsLogPAN(cardNumber string) {
	// PAN-TYPE also fires on cardNumber parameter (string type)
	slog.Info("payment processed", "card", cardNumber) // PAN-LOGGER
}

// --- PAN-ZEROING: sensitive []byte not zeroed after use ---
func allViolationsNoZeroing() {
	cvvData := []byte("sensitive-cvv")
	_ = len(cvvData)
	// cvvData is never zeroed -> PAN-ZEROING
}

// =============================================================================
// Crypto Scanner rules
// =============================================================================

// --- CRYPTO-WEAK-HASH: md5 used with sensitive context ---
func allViolationsWeakHash(password string) []byte {
	h := md5.New() // CRYPTO-WEAK-HASH (md5 near password context)
	h.Write([]byte(password))
	return h.Sum(nil)
}

// --- CRYPTO-HARDCODED-KEY: keyword "Key" with literal value ---
var allViolationsEncryptionKey = "supersecretkey1234567890abcdef" // CRYPTO-HARDCODED-KEY

// --- CRYPTO-PLAIN-HTTP: plain HTTP URL for payment endpoint ---
var allViolationsPaymentURL = "http://payment.example.com/api/charge" // CRYPTO-PLAIN-HTTP

// =============================================================================
// TLS Scanner rules
// =============================================================================

// --- TLS-INSECURE-SKIP-VERIFY: InsecureSkipVerify set to true ---
var allViolationsInsecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // TLS-INSECURE-SKIP-VERIFY
		},
	},
}

// --- TLS-WEAK-VERSION: MinVersion below TLS 1.2 ---
var allViolationsWeakTLS = &tls.Config{
	MinVersion: tls.VersionTLS10, // TLS-WEAK-VERSION
}

// --- TLS-WEAK-CIPHER: weak cipher suite ---
var allViolationsWeakCipher = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA, // TLS-WEAK-CIPHER
	},
}

// =============================================================================
// Error Scanner rules
// =============================================================================

// --- ERR-LEAK-DIRECT: payment handler writing err.Error() to response ---
func AllViolationsHandlePaymentError(w http.ResponseWriter, r *http.Request) {
	err := fmt.Errorf("database connection failed: host=db.internal password=secret")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError) // ERR-LEAK-DIRECT
	}
}

// =============================================================================
// Auth Scanner rules
// =============================================================================

// --- AUTH-HARDCODED-PWD: hardcoded password in variable ---
var allViolationsAdminPassword = "admin123secret" // AUTH-HARDCODED-PWD

// --- AUTH-WEAK-POLICY: password length check below PCI DSS v4.0 minimum of 12 ---
func allViolationsValidatePassword(password string) error {
	if len(password) < 8 { // AUTH-WEAK-POLICY (threshold 8 < 12)
		return fmt.Errorf("password too short")
	}
	return nil
}

// --- AUTH-MISSING-MFA: payment handler without MFA middleware ---
func allViolationsHandlePaymentAuth(w http.ResponseWriter, r *http.Request) {
	// AUTH-MISSING-MFA: payment route handler with no MFA check
	fmt.Fprintf(w, "payment processed")
}

// =============================================================================
// Audit Scanner rules
// =============================================================================

// --- AUDIT-NO-LOG: payment handler with no logging calls ---
func AllViolationsHandlePaymentNoLog(w http.ResponseWriter, r *http.Request) {
	// No slog/log call -> AUDIT-NO-LOG
	w.Write([]byte("payment processed"))
}

// =============================================================================
// Retention Scanner rules
// =============================================================================

// Simulated Redis client for retention pattern matching.
type allViolationsRedisClient struct{}

func (r *allViolationsRedisClient) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {
}

// --- RET-REDIS-NO-TTL: Redis Set with TTL=0 on sensitive data ---
func AllViolationsStoreCardNoTTL(w http.ResponseWriter, r *http.Request) {
	rdb := &allViolationsRedisClient{}
	rdb.Set(nil, "card_data", "4111111111111111", 0) // RET-REDIS-NO-TTL
}

// --- RET-ZERO-DEFER-ONLY: defer zeroing executes after response ---
func AllViolationsProcessPaymentDefer(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111111111111111")
	defer allViolationsClearData(cardData) // RET-ZERO-DEFER-ONLY
	allViolationsAuthorize(cardData)
	w.Write([]byte("ok"))
}

func allViolationsAuthorize(_ []byte) {}
func allViolationsClearData(_ []byte) {}

// =============================================================================
// Script Scanner rules (Go handler side)
// =============================================================================

// --- CSP-MISSING: HTML-serving payment handler without CSP header ---
// Uses template.Execute to be detected as HTML response (D-07)
func AllViolationsHandlePaymentPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("page").Parse("<html><body>Pay</body></html>"))
	tmpl.Execute(w, nil) // responseHTML detected, CSP-MISSING fires at HIGH
}

// --- CSP-UNSAFE-INLINE: CSP with unsafe-inline ---
func AllViolationsHandleCheckoutUnsafe(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'") // CSP-UNSAFE-INLINE
	tmpl := template.Must(template.New("checkout").Parse("<html><body>Checkout</body></html>"))
	tmpl.Execute(w, nil)
}

// --- CSP-UNSAFE-EVAL: CSP with unsafe-eval ---
func AllViolationsHandleTransactionEval(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-eval'") // CSP-UNSAFE-EVAL
	tmpl := template.Must(template.New("tx").Parse("<html><body>Transaction</body></html>"))
	tmpl.Execute(w, nil)
}

// =============================================================================
// Ensure all variables/imports are used
// =============================================================================

func init() {
	_ = allViolationsTestCard
	_ = allViolationsEncryptionKey
	_ = allViolationsPaymentURL
	_ = allViolationsInsecureClient
	_ = allViolationsWeakTLS
	_ = allViolationsWeakCipher
	_ = allViolationsAdminPassword
	_ = json.Marshal
}
