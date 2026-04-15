// Package analysis provides shared data classification utilities for PCI DSS
// scanners. It identifies sensitive data identifiers (struct fields, variable
// names) that may contain PAN, CVV, or other cardholder/authentication data.
package analysis

import "strings"

// SensitiveDataKeywords is the union of PAN/CVV/payment-related keywords used
// for data retention scanning (PCI DSS 3.2.1, 3.3.1). Substring matching is
// used (unlike panscanner's exact-match) for broader coverage: "cardData",
// "panToken", "cvvCache" should all match.
var SensitiveDataKeywords = []string{
	"card",
	"pan",
	"cvv",
	"cvc",
	"payment",
	"sensitive",
	"cardholder",
	"sad",
	"auth_data",
	"creditcard",
	"debitcard",
	"accountnumber",
	"track",
	"pinblock",
}

// normalize strips underscores and hyphens, then lowercases the result.
func normalize(name string) string {
	var sb strings.Builder
	sb.Grow(len(name))
	for _, r := range name {
		if r == '_' || r == '-' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// normalizedKeywords holds the pre-normalized versions of SensitiveDataKeywords
// (underscores/hyphens stripped, lowercased) for efficient substring matching.
var normalizedKeywords []string

func init() {
	normalizedKeywords = make([]string, len(SensitiveDataKeywords))
	for i, kw := range SensitiveDataKeywords {
		normalizedKeywords[i] = normalize(kw)
	}
}

// isSensitive checks whether the normalized name contains any keyword from
// SensitiveDataKeywords as a substring.
func isSensitive(name string) bool {
	norm := normalize(name)
	for _, kw := range normalizedKeywords {
		if strings.Contains(norm, kw) {
			return true
		}
	}
	return false
}

// IsSensitiveFieldName returns true if the struct field name contains any
// PAN/CVV/payment-related keyword after normalization.
func IsSensitiveFieldName(name string) bool {
	return isSensitive(name)
}

// IsSensitiveVarName returns true if the variable name contains any
// PAN/CVV/payment-related keyword after normalization. Uses the same logic as
// IsSensitiveFieldName, exposed separately for clarity in call sites.
func IsSensitiveVarName(name string) bool {
	return isSensitive(name)
}
