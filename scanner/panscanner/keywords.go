// Package panscanner implements PAN/cardholder data detection primitives.
package panscanner

import "strings"

// sensitiveKeywords contains all 18 PAN/cardholder data keywords from
// in normalized form (lowercase, no separators).
var sensitiveKeywords = map[string]bool{
	"pan":                  true,
	"cvv":                  true,
	"cvc":                  true,
	"cardnumber":           true,
	"cardnum":              true,
	"creditcard":           true,
	"debitcard":            true,
	"accountnumber":        true,
	"expiry":               true,
	"primaryaccountnumber": true,
	"securitycode":         true,
	"verificationcode":     true,
	"cardholder":           true,
	"trackdata":            true,
	"track1":               true,
	"track2":               true,
	"magneticstripe":       true,
	"pinblock":             true,
}

// testPrefixes are variable name prefixes that indicate test/mock data.
var testPrefixes = []string{"test", "mock", "fake", "dummy", "stub"}

// Normalize strips underscores and hyphens from name and lowercases it.
// This enables matching across naming conventions: card_number, cardNumber,
// CardNumber, CARD_NUMBER, card-number all normalize to "cardnumber".
func Normalize(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		if r == '_' || r == '-' {
			continue
		}
		// Manual lowercase for ASCII (avoids unicode overhead).
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// IsSensitiveKeyword returns true if name matches one of the 18 PAN/cardholder
// sensitive keywords after normalization (exact match, not substring).
// "pan" matches, but "panel", "span", "expand" do not.
func IsSensitiveKeyword(name string) bool {
	return sensitiveKeywords[Normalize(name)]
}

// HasTestPrefix returns true if name starts with a test variable prefix
// (test, mock, fake, dummy, stub) after lowercasing.
func HasTestPrefix(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	for _, prefix := range testPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}
