package scriptscanner

import "strings"

// CSPAnalysis contains the results of parsing a Content-Security-Policy header value.
type CSPAnalysis struct {
	HasScriptSrc        bool // explicit script-src directive found
	HasDefaultSrc       bool // explicit default-src found (fallback)
	NoScriptRestriction bool // neither script-src nor default-src present
	HasUnsafeInline     bool // 'unsafe-inline' in script-src/default-src (after CSP3 override check)
	HasUnsafeEval       bool // 'unsafe-eval' in script-src/default-src
	HasNonce            bool // 'nonce-*' present
	HasStrictDynamic    bool // 'strict-dynamic' present
	ValueAnalyzable     bool // true if CSP value was a string literal we could parse
}

// parseCSP parses a CSP header value and analyzes its script-src (or default-src
// as fallback) directive for unsafe patterns per logic.
//
// CSP format: "directive1 value1 value2; directive2 value3 value4"
//
// CSP3 override rule: if unsafe-inline is present alongside a nonce or
// strict-dynamic, browsers ignore unsafe-inline. This function applies that
// rule to avoid false positives.
func parseCSP(cspValue string) CSPAnalysis {
	result := CSPAnalysis{
		ValueAnalyzable: true,
	}

	directives := strings.Split(cspValue, ";")

	var scriptSrcValues []string
	var defaultSrcValues []string
	foundScriptSrc := false
	foundDefaultSrc := false

	for _, d := range directives {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		parts := strings.Fields(d)
		if len(parts) == 0 {
			continue
		}

		name := strings.ToLower(parts[0])
		values := parts[1:]

		switch name {
		case "script-src":
			foundScriptSrc = true
			scriptSrcValues = values
		case "default-src":
			foundDefaultSrc = true
			defaultSrcValues = values
		}
	}

	result.HasScriptSrc = foundScriptSrc
	result.HasDefaultSrc = foundDefaultSrc

	// Determine which values to analyze: script-src takes priority, default-src
	// is the CSP spec fallback.
	var valuesToAnalyze []string
	switch {
	case foundScriptSrc:
		valuesToAnalyze = scriptSrcValues
	case foundDefaultSrc:
		valuesToAnalyze = defaultSrcValues
	default:
		// Neither script-src nor default-src: no script source restriction.
		result.NoScriptRestriction = true
		return result
	}

	// Analyze the directive values for unsafe patterns.
	analyzeValues(valuesToAnalyze, &result)

	// CSP3 override: if nonce or strict-dynamic is present, browsers ignore
	// unsafe-inline. This does NOT apply to unsafe-eval.
	if result.HasUnsafeInline && (result.HasNonce || result.HasStrictDynamic) {
		result.HasUnsafeInline = false
	}

	return result
}

// analyzeValues inspects CSP directive values for unsafe-inline, unsafe-eval,
// nonce-*, and strict-dynamic tokens. All comparisons are case-insensitive.
func analyzeValues(values []string, result *CSPAnalysis) {
	for _, v := range values {
		lower := strings.ToLower(v)

		switch {
		case lower == "'unsafe-inline'":
			result.HasUnsafeInline = true
		case lower == "'unsafe-eval'":
			result.HasUnsafeEval = true
		case lower == "'strict-dynamic'":
			result.HasStrictDynamic = true
		case strings.HasPrefix(lower, "'nonce-"):
			result.HasNonce = true
		}
	}
}
