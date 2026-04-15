// Package testdata contains test fixtures for PCI DSS compliance scanning.
// This file contains INTENTIONAL PAN/CVV violations for testing. DO NOT use as example code.
package testdata

import "fmt"

// --- PAN-01 violations (keyword detection in various contexts) ---

// VIOLATION: PAN-KEYWORD CRITICAL - PAN in struct field with payment context (3.3.1)
// VIOLATION: PAN-KEYWORD CRITICAL - CVV in struct field with payment context (3.3.1)
// VIOLATION: PAN-TYPE MEDIUM - CardNumber declared as string (3.5.1) [D-05: defense-in-depth, not violation]
// VIOLATION: PAN-TYPE MEDIUM - CVV declared as string (3.5.1) [D-05: defense-in-depth, not violation]
type PaymentData struct {
	CardNumber string  // sensitive field
	CVV        string  // sensitive field
	Amount     float64 // payment indicator
	Currency   string  // payment indicator
	Merchant   string  // payment indicator
}

// VIOLATION: PAN-KEYWORD HIGH - PAN in struct field without payment context (3.3.1)
// VIOLATION: PAN-TYPE MEDIUM - PAN declared as string (3.5.1) [D-05: defense-in-depth, not violation]
type GenericData struct {
	PAN   string
	Label string
	Count int
}

// D-06: PAN-KEYWORD removed from function params and local vars
// VIOLATION: PAN-TYPE MEDIUM - cvv declared as string (3.5.1) [D-05: defense-in-depth, not violation]
func ProcessCard(cvv string, amount float64, currency string) error {
	_ = cvv
	return nil
}

// D-06: PAN-KEYWORD removed from local variables -- no findings here
func handleRequest() {
	cardNum := "some-value"
	_ = cardNum
}

// D-06: PAN-KEYWORD removed from function params
// VIOLATION: PAN-TYPE MEDIUM - cardNumber declared as string (3.5.1) [D-05: defense-in-depth, not violation]
// VIOLATION: PAN-LOGGER CRITICAL - cardNumber passed to fmt.Printf (3.3.1)
func logPayment(cardNumber string) {
	fmt.Printf("card: %s\n", cardNumber)
}

// VIOLATION: PAN-KEYWORD HIGH - Sensitive JSON tag card_number (3.3.1)
type APIRequest struct {
	Token   string  `json:"card_number"`
	Amount  float64 `json:"amount"`
	Payment string  `json:"payment_type"`
}

// --- PAN-03 violations (Luhn+IIN literals) ---

// VIOLATION: PAN-LITERAL MEDIUM - Hardcoded test card number Visa (3.4.1)
var testVisaCard = "4242424242424242"

// VIOLATION: PAN-LITERAL MEDIUM - Hardcoded test card number Mastercard (3.4.1)
var mcCard = "5500000000000004"

// VIOLATION: PAN-LITERAL MEDIUM - Hardcoded test card number Amex (3.4.1)
var amexCard = "378282246310005"

// --- PAN-04 violations (string vs []byte) ---
// Already covered above in PaymentData, GenericData, and function params.

// NO VIOLATION: correct []byte type for sensitive data
type SecurePayment struct {
	CardData []byte
	Amount   float64
	Currency string
}

// --- PAN-05 violations (missing zeroing of local []byte variable) ---

// VIOLATION: PAN-ZEROING MEDIUM - Missing explicit zeroing of sensitive []byte data (3.5.1)
func processSecure() {
	cvv := []byte("sensitive-data")
	_ = len(cvv)
	// cvv is never zeroed
}

// NO VIOLATION: sensitive []byte is properly zeroed
func processAndZero() {
	pan := []byte("sensitive-data")
	_ = len(pan)
	for i := range pan {
		pan[i] = 0
	}
}

// Ensure variables are used to prevent compilation errors.
func init() {
	_ = testVisaCard
	_ = mcCard
	_ = amexCard
}
