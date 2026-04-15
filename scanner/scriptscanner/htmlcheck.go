package scriptscanner

import (
	"bytes"
	"io"
	"os"
	"strings"

	"golang.org/x/net/html"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// scriptTagInfo stores information about a <script> tag found during tokenization.
type scriptTagInfo struct {
	HasSrc       bool
	SrcValue     string
	HasIntegrity bool
	HasNonce     bool
	Line         int
}

// metaCSPInfo stores information about a <meta http-equiv="Content-Security-Policy"> tag.
type metaCSPInfo struct {
	Content string
	Line    int
}

// paymentKeywords are form/input attribute values that indicate a payment page.
// Case-insensitive substring match against name, id, class, type, action,
// placeholder attributes.
var paymentKeywords = []string{
	"card", "cvv", "pan", "expiry", "checkout", "payment",
	"credit", "cardholder", "account-number", "card-number",
	"cvc", "ccn",
}

// scanHTMLFile tokenizes an HTML file and detects SRI/nonce/CSP violations.
// Returns findings, line count, and any error.
func (s *ScriptScanner) scanHTMLFile(path string) ([]scanner.Finding, int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}

	lineCount := bytes.Count(content, []byte("\n")) + 1

	z := html.NewTokenizer(bytes.NewReader(content))

	var scripts []scriptTagInfo
	hasPaymentKeywords := false
	var metaCSP *metaCSPInfo

	// searchOffset tracks position in content for line estimation.
	searchOffset := 0

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			// golang.org/x/net/html tokenizer handles malformed HTML gracefully
			// (T-07-08). On non-EOF errors we stop tokenizing but do not fail
			// the scan — we process whatever we already collected.
			break
		}

		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tn, hasAttr := z.TagName()
		tagName := string(tn) // CRITICAL: convert to string immediately (Pitfall 2)

		var attrs map[string]string
		if hasAttr {
			attrs = readAttrs(z)
		} else {
			attrs = make(map[string]string)
		}

		switch tagName {
		case "script":
			si := collectScriptTag(attrs)
			si.Line = estimateLine(content, "<script", &searchOffset)
			scripts = append(scripts, si)
		case "meta":
			checkMetaCSP(attrs, &metaCSP, content, &searchOffset)
		case "input", "form":
			checkPaymentKeywords(attrs, &hasPaymentKeywords)
		}
	}

	var findings []scanner.Finding

	// Script tag findings (SCRIPT-03, SCRIPT-04).
	for _, si := range scripts {
		if si.HasSrc && !si.HasIntegrity {
			// External script without SRI.
			if hasPaymentKeywords {
				findings = append(findings, scanner.Finding{
					RuleID:        "SRI-MISSING-PAYMENT",
					Severity:      scanner.SeverityCritical,
					RequirementID: "6.4.3",
					FilePath:      path,
					Line:          si.Line,
					Description:   "External script '" + si.SrcValue + "' loaded without integrity attribute (SRI) in payment page template. PCI DSS 6.4.3 requires script integrity verification on payment pages.",
					Suggestion:    "Add integrity='sha384-...' crossorigin='anonymous' to the script tag. Generate hash with: shasum -b -a 384 script.js | xxd -r -p | base64",
				})
			} else {
				findings = append(findings, scanner.Finding{
					RuleID:        "SRI-MISSING",
					Severity:      scanner.SeverityHigh,
					RequirementID: "6.4.3",
					FilePath:      path,
					Line:          si.Line,
					Description:   "External script '" + si.SrcValue + "' loaded without integrity attribute (SRI). If this page handles payment data, this violates PCI DSS 6.4.3. If not a payment page, suppress with // pci-ignore: not-payment-page",
					Suggestion:    "Add integrity='sha384-...' crossorigin='anonymous' to the script tag.",
				})
			}
		}
		if !si.HasSrc && !si.HasNonce {
			// Inline script without nonce.
			if hasPaymentKeywords {
				findings = append(findings, scanner.Finding{
					RuleID:        "NONCE-MISSING-PAYMENT",
					Severity:      scanner.SeverityCritical,
					RequirementID: "6.4.3",
					FilePath:      path,
					Line:          si.Line,
					Description:   "Inline script without nonce attribute in payment page template. PCI DSS 6.4.3 requires script authorization via nonce or hash on payment pages.",
					Suggestion:    "Add nonce='<random-value>' to the script tag. Generate a unique nonce per request on the server side.",
				})
			} else {
				findings = append(findings, scanner.Finding{
					RuleID:        "NONCE-MISSING",
					Severity:      scanner.SeverityHigh,
					RequirementID: "6.4.3",
					FilePath:      path,
					Line:          si.Line,
					Description:   "Inline script without nonce attribute. If this page handles payment data, this violates PCI DSS 6.4.3. If not a payment page, suppress with // pci-ignore: not-payment-page",
					Suggestion:    "Add nonce='<random-value>' to the script tag. Generate a unique nonce per request on the server side.",
				})
			}
		}
	}

	// Meta tag CSP findings.
	if metaCSP != nil {
		analysis := parseCSP(metaCSP.Content)
		if analysis.HasUnsafeInline || analysis.HasUnsafeEval {
			findings = append(findings, scanner.Finding{
				RuleID:        "META-CSP-UNSAFE",
				Severity:      scanner.SeverityHigh,
				RequirementID: "6.4.3",
				FilePath:      path,
				Line:          metaCSP.Line,
				Description:   "Content-Security-Policy meta tag contains unsafe directives (unsafe-inline or unsafe-eval). PCI DSS 6.4.3 requires secure script execution policies on payment pages.",
				Suggestion:    "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes for inline scripts instead.",
			})
		} else {
			findings = append(findings, scanner.Finding{
				RuleID:        "META-CSP-ONLY",
				Severity:      scanner.SeverityMedium,
				RequirementID: "6.4.3",
				FilePath:      path,
				Line:          metaCSP.Line,
				Description:   "CSP set via meta tag only. HTTP header is stronger: meta tag enforced after HTML parsing begins -- scripts before meta tag may execute. Also: frame-ancestors, sandbox directives not supported in meta tags. PCI DSS 6.4.3 recommends HTTP header for payment pages.",
				Suggestion:    "Set Content-Security-Policy via HTTP response header instead of (or in addition to) meta tag.",
			})
		}
	}

	// FIM informational finding (SCRIPT-05,, ).
	if hasPaymentKeywords {
		findings = append(findings, scanner.Finding{
			RuleID:        "FIM-REQUIRED",
			Severity:      scanner.SeverityMedium,
			RequirementID: "11.6.1",
			FilePath:      path,
			Line:          1,
			Description:   "PCI DSS 11.6.1 requires change and tamper detection for payment page scripts -- at minimum weekly, ideally real-time. Static analysis cannot verify runtime monitoring. Recommended: implement file integrity monitoring for JS files served on payment pages (Wazuh, OSSEC, or custom hash comparison in CI/CD pipeline). This finding requires manual verification.",
			Suggestion:    "Implement file integrity monitoring (FIM) for JavaScript files served on payment pages. Consider Wazuh, OSSEC, or hash-based verification in CI/CD.",
		})
	}

	return findings, lineCount, nil
}

// readAttrs reads all attributes from the current token and returns them as
// a map. Keys and values are converted to string immediately to avoid buffer
// reuse issues (Pitfall 2).
func readAttrs(z *html.Tokenizer) map[string]string {
	attrs := make(map[string]string)
	for {
		key, val, more := z.TagAttr()
		k := string(key) // CRITICAL: convert immediately
		v := string(val) // CRITICAL: convert immediately
		if k != "" {
			attrs[k] = v
		}
		if !more {
			break
		}
	}
	return attrs
}

// collectScriptTag extracts relevant attributes from a <script> tag.
func collectScriptTag(attrs map[string]string) scriptTagInfo {
	si := scriptTagInfo{}
	if src, ok := attrs["src"]; ok && src != "" {
		si.HasSrc = true
		si.SrcValue = src
	}
	if _, ok := attrs["integrity"]; ok {
		si.HasIntegrity = true
	}
	if _, ok := attrs["nonce"]; ok {
		si.HasNonce = true
	}
	return si
}

// checkMetaCSP checks if a <meta> tag is a Content-Security-Policy definition.
// Case-insensitive comparison on http-equiv.
func checkMetaCSP(attrs map[string]string, metaCSP **metaCSPInfo, content []byte, searchOffset *int) {
	httpEquiv, ok := attrs["http-equiv"]
	if !ok {
		return
	}
	if !strings.EqualFold(httpEquiv, "Content-Security-Policy") {
		return
	}
	cspContent, ok := attrs["content"]
	if !ok {
		return
	}
	*metaCSP = &metaCSPInfo{
		Content: cspContent,
		Line:    estimateLine(content, "<meta", searchOffset),
	}
}

// checkPaymentKeywords checks form/input element attributes for payment-related
// keywords. Sets *hasPayment = true on first match.
func checkPaymentKeywords(attrs map[string]string, hasPayment *bool) {
	if *hasPayment {
		return // Already detected.
	}

	// Attributes to check for payment keywords.
	attrNames := []string{"name", "id", "class", "type", "action", "placeholder"}
	for _, attrName := range attrNames {
		val, ok := attrs[attrName]
		if !ok {
			continue
		}
		valLower := strings.ToLower(val)
		for _, keyword := range paymentKeywords {
			if strings.Contains(valLower, keyword) {
				*hasPayment = true
				return
			}
		}
	}
}

// estimateLine finds the next occurrence of searchTag in content starting from
// *startFrom, counts newlines before it, and returns a 1-based line number.
// Updates *startFrom to just past the found position for subsequent calls.
// Returns 0 if not found.
func estimateLine(content []byte, searchTag string, startFrom *int) int {
	idx := bytes.Index(content[*startFrom:], []byte(searchTag))
	if idx < 0 {
		return 0
	}
	absPos := *startFrom + idx
	line := 1 + bytes.Count(content[:absPos], []byte("\n"))
	*startFrom = absPos + len(searchTag)
	return line
}
