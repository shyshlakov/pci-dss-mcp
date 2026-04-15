// Package keywords provides shared keyword matching for payment-related
// function names and URL path segments. It is the single source of truth
// for payment keyword lists, consumed by both errorscanner and authscanner.
package keywords

import "strings"

// PaymentPathSegments are URL path segments that indicate a payment context.
// A path is considered payment-related if any of its slash-separated segments
// (case-insensitive) exactly matches one of these entries.
var PaymentPathSegments = []string{
	"pay",
	"payment",
	"payments",
	"checkout",
	"check-out",
	"card",
	"cards",
	"transaction",
	"transactions",
	"charge",
	"charges",
	"refund",
	"refunds",
	"transfer",
	"transfers",
	"billing",
	"bill",
	"invoice",
	"invoices",
	"order",
	"orders",
	"purchase",
	"purchases",
	"tokenize",
	"detokenize",
	"token",
	"vault",
}

// PaymentFuncKeywords are substrings that identify payment-context functions.
// A function is considered payment-related if its lowercased name contains
// any of these keywords.
var PaymentFuncKeywords = []string{
	"pay",
	"payment",
	"card",
	"checkout",
	"transaction",
	"charge",
	"refund",
	"transfer",
	"billing",
	"invoice",
	"purchase",
	"tokenize",
	"detokenize",
	"processcard",
	"handlecard",
}

// Tier 1 keywords: CRITICAL if no logging.
// Core payment operations where missing audit logging is a direct PCI DSS violation.
var tier1Keywords = []string{
	"pay", "payment", "checkout", "charge", "transaction", "refund",
	"transfer", "billing", "card", "vault", "tokenize",
}

// Tier 2 keywords: HIGH if no logging.
// Payment-adjacent operations that should be logged.
var tier2Keywords = []string{
	"invoice", "order", "purchase", "settlement", "merchant",
}

// Tier 3 keywords: MEDIUM if no logging, only when same file has Tier 1.
// Generic operations that become payment-relevant through co-location.
var tier3Keywords = []string{
	"callback", "webhook", "notify",
}

// PaymentFuncTier returns the payment tier (1/2/3) for a function name,
// or 0 if not payment-related.
// Tier 3 only returns 3 when fileTier1Present is true (co-location rule).
// Tier 1 is checked first to ensure highest-severity match wins.
func PaymentFuncTier(funcName string, fileTier1Present bool) int {
	lower := strings.ToLower(funcName)
	for _, kw := range tier1Keywords {
		if strings.Contains(lower, kw) {
			return 1
		}
	}
	for _, kw := range tier2Keywords {
		if strings.Contains(lower, kw) {
			return 2
		}
	}
	if fileTier1Present {
		for _, kw := range tier3Keywords {
			if strings.Contains(lower, kw) {
				return 3
			}
		}
	}
	return 0
}

// FileHasTier1Keyword checks if any function declaration in the same file
// has a Tier 1 payment keyword. Used for Tier 3 co-location check.
func FileHasTier1Keyword(funcNames []string) bool {
	for _, name := range funcNames {
		lower := strings.ToLower(name)
		for _, kw := range tier1Keywords {
			if strings.Contains(lower, kw) {
				return true
			}
		}
	}
	return false
}

// pathSegmentSet is a pre-computed set of lowercased path segments for O(1) lookup.
var pathSegmentSet map[string]bool

func init() {
	pathSegmentSet = make(map[string]bool, len(PaymentPathSegments))
	for _, seg := range PaymentPathSegments {
		pathSegmentSet[strings.ToLower(seg)] = true
	}
}

// matchesPaymentFuncKeyword reports whether funcName contains any
// payment-related keyword (case-insensitive substring match). Used
// exclusively by the multi-signal scorer's Signal 1. External callers
// must use IsPaymentContext.
func matchesPaymentFuncKeyword(funcName string) bool {
	lower := strings.ToLower(funcName)
	for _, kw := range PaymentFuncKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// IsPaymentPath returns true if any slash-separated segment of the path
// exactly matches (case-insensitive) a payment path segment.
func IsPaymentPath(path string) bool {
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if pathSegmentSet[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}
