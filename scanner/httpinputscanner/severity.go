package httpinputscanner

import (
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// panKeywords are the substring tokens that promote HTTP-INPUT-LOG severity
// from MEDIUM to HIGH per D-08. Comparison is case-insensitive substring on
// the source identifier (path slot name, header name, query param name, body
// struct field name, or struct type name for whole-struct sinks).
//
// Notable omission: "bin" - while semantically a Bank Identification Number
// is payment-related, the substring "bin" overlaps with too many neutral tokens
// (binding, binary, etc.) to safely promote without context. The fixture
// contract treats path slot "bin" as MEDIUM. PAN promotion targets the
// "pan" / "primaryaccountnumber" / "card_number" / "cvv" / "iban" identifiers.
var panKeywords = []string{
	"pan",
	"primaryaccountnumber",
	"cardnumber",
	"iban",
	"cvv",
	"cvc",
	"securitycode",
	"apikey",
	"accountnumber",
}

// safeHeaderIdentifiers are HTTP header names whose values are conventionally
// safe to log (correlation IDs, user agent, etc.). When the ONLY tainted
// source feeding a log sink is one of these headers, the scanner suppresses
// the finding to avoid documented false positives. PCI DSS leakage policy
// applies to PAN/SAD/auth secrets - request_id is none of those.
var safeHeaderIdentifiers = map[string]bool{
	"X-Request-ID":     true,
	"X-Request-Id":     true,
	"x-request-id":     true,
	"X-Correlation-ID": true,
	"X-Correlation-Id": true,
	"x-correlation-id": true,
	"X-Trace-ID":       true,
	"X-Trace-Id":       true,
	"x-trace-id":       true,
	"User-Agent":       true,
	"user-agent":       true,
	"Referer":          true,
	"referer":          true,
}

// isSafeIdentifier reports whether the source identifier introducing taint
// matches a known-safe header / parameter name. Used to suppress documented
// false-positive emissions on audit-middleware patterns.
func isSafeIdentifier(identifier string) bool {
	if identifier == "" {
		return false
	}
	if safeHeaderIdentifiers[identifier] {
		return true
	}
	lc := strings.ToLower(identifier)
	switch lc {
	case "x-request-id", "x-correlation-id", "x-trace-id", "user-agent", "referer", "request-id", "trace-id":
		return true
	}
	return false
}

// computeSeverity returns the finding severity for a USER_INPUT-tainted log
// sink. MEDIUM is the recall-biased default; HIGH fires when the source
// identifier matches a known PAN keyword.
func computeSeverity(ctx UserInputContext) scanner.Severity {
	if matchesPanKeyword(ctx.Identifier) {
		return scanner.SeverityHigh
	}
	return scanner.SeverityMedium
}

// matchesPanKeyword reports whether identifier carries a PAN-keyword
// substring. Comparison normalizes case and strips common separators so
// "card_number" / "CardNumber" / "CARDNUMBER" all match.
func matchesPanKeyword(identifier string) bool {
	if identifier == "" {
		return false
	}
	norm := strings.ToLower(identifier)
	norm = strings.ReplaceAll(norm, "_", "")
	norm = strings.ReplaceAll(norm, "-", "")
	for _, kw := range panKeywords {
		k := strings.ReplaceAll(kw, "_", "")
		if strings.Contains(norm, k) {
			return true
		}
	}
	return false
}

// relatedRequirementsForLog returns the related requirement IDs for a
// HTTP-INPUT-LOG finding. PAN-keyword promotion adds 3.3.1 + 3.5.1.
func relatedRequirementsForLog(severity scanner.Severity) []string {
	if severity == scanner.SeverityHigh {
		return []string{"3.3.1", "3.5.1"}
	}
	return nil
}
