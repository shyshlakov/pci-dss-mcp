package httpinputscanner

import (
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// panKeywords promote HTTP-INPUT-LOG severity to HIGH when the field name
// matches. Substring match is case-insensitive on the normalized identifier
// (lowercase, separators stripped).
//
// Notable omission: "bin" - the substring overlaps with neutral tokens like
// "binding", "binary", "sbin"; promotion would produce false positives. The
// fixture contract treats path slot "bin" as MEDIUM.
//
// "apikey" was reclassified to authSecretKeywords - an API key is an auth
// secret, not cardholder data. Related requirement changes from
// [3.3.1, 3.5.1] to [8.6.2].
var panKeywords = []string{
	"pan",
	"primaryaccountnumber",
	"cardnumber",
	"iban",
	"cvv",
	"cvc",
	"securitycode",
	"accountnumber",
}

// authSecretKeywords promote HTTP-INPUT-LOG severity to HIGH when the field
// name signals an authentication secret. Even when the value passed through a
// format-validator sanitizer (uuid.Parse, strconv.Atoi), the field name itself
// signals secret context and the rule fires. PCI DSS requirement is 8.6.2
// (system / application authentication), distinct from PAN/CHD storage
// requirements 3.3.1 / 3.5.1.
var authSecretKeywords = []string{
	"apikey",
	"token",
	"password",
	"secret",
	"bearer",
	"auth",
}

// genericIDKeywords SUPPRESS HTTP-INPUT-LOG entirely. Server-validated
// correlation IDs are recommended observability practice. Adversarial
// mis-naming (an api_key labelled "widget_id") is an accepted false-negative
// trade: source-code access is required to mis-name, downstream review catches
// it, and a future user-override mechanism allows project-specific tightening.
var genericIDKeywords = []string{
	"requestid",
	"traceid",
	"widgetid",
	"tenantid",
	"merchantid",
	"correlationid",
	"spanid",
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

type severityClass int

const (
	severityClassNone severityClass = iota
	severityClassPanCHD
	severityClassAuthSecret
	severityClassGenericID
	severityClassBodySource
)

func classifyKeyword(identifier string) severityClass {
	if identifier == "" {
		return severityClassNone
	}
	norm := normalizeIdentifier(identifier)
	// Generic-ID is checked first because some correlation-ID tokens
	// (e.g. "spanid") substring-overlap PAN tokens ("pan"). Generic-ID
	// keywords are never substrings of PAN or auth-secret keywords, so
	// the reverse precedence cannot regress PAN/auth-secret matches.
	for _, kw := range genericIDKeywords {
		if strings.Contains(norm, kw) {
			return severityClassGenericID
		}
	}
	for _, kw := range panKeywords {
		if strings.Contains(norm, kw) {
			return severityClassPanCHD
		}
	}
	for _, kw := range authSecretKeywords {
		if strings.Contains(norm, kw) {
			return severityClassAuthSecret
		}
	}
	return severityClassNone
}

func normalizeIdentifier(identifier string) string {
	norm := strings.ToLower(identifier)
	norm = strings.ReplaceAll(norm, "_", "")
	norm = strings.ReplaceAll(norm, "-", "")
	return norm
}

// computeSeverity returns the finding severity for a USER_INPUT-tainted
// HTTP-INPUT-LOG sink, plus a shouldEmit flag. shouldEmit=false means the
// finding is SUPPRESSED. Priority order:
//  1. Keyword classes evaluated first: PAN/CHD HIGH, auth-secret HIGH,
//     generic-ID SUPPRESS.
//  2. If no keyword class matched, check the source-chain origin: if the
//     taint flowed from a body-decoder source (request body read, JSON
//     decode, framework body-binding), promote to HIGH regardless of
//     identifier - body content is unknown and may carry PAN/CVV.
//  3. Otherwise fall through to MEDIUM default.
//
// Generic-ID class deliberately wins over the body-source override: a
// validated correlation ID extracted from a decoded body (e.g. struct field
// `WidgetID` after ShouldBindJSON) is observability-safe.
func computeSeverity(ctx UserInputContext) (scanner.Severity, bool) {
	switch classifyKeyword(ctx.Identifier) {
	case severityClassPanCHD, severityClassAuthSecret:
		return scanner.SeverityHigh, true
	case severityClassGenericID:
		return "", false
	}
	if ctx.SourceIsBodyDecoder {
		return scanner.SeverityHigh, true
	}
	return scanner.SeverityMedium, true
}

func matchesPanKeyword(identifier string) bool {
	return classifyKeyword(identifier) == severityClassPanCHD
}

// relatedRequirementsForLog dispatches by keyword class. The body-source
// override has no canonical related-reqs because body content shape is
// unknown.
func relatedRequirementsForLog(severity scanner.Severity, ctx UserInputContext) []string {
	if severity != scanner.SeverityHigh {
		return nil
	}
	switch classifyKeyword(ctx.Identifier) {
	case severityClassPanCHD:
		return []string{"3.3.1", "3.5.1"}
	case severityClassAuthSecret:
		return []string{"8.6.2"}
	}
	return nil
}
