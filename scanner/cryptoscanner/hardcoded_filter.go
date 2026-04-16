package cryptoscanner

import (
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

var (
	httpHeaderPrefixPattern = regexp.MustCompile(`(?i)^(X-|Content-|Accept-|Authorization-|Cache-Control|Pragma|If-None-Match)`)
	snakeCasePattern        = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)+$`)
	filterCamelCasePattern  = regexp.MustCompile(`^[a-zA-Z]+([A-Z][a-z]+)*$`)
	pureHexPattern          = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	base64CharsetPattern    = regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`)
	constantsFilePattern    = regexp.MustCompile(`(?:^|/)(?:errors|headers|logger/keys|constant[^/]*)\.go$`)
	errVarPattern           = regexp.MustCompile(`^Err[A-Z]`)
)

func ApplyHardcodedFilter(finding scanner.Finding, varName, strVal, initExpr string) scanner.Finding {
	if isSentinelError(varName, strVal, initExpr) {
		finding.Severity = scanner.SeverityInfo
		finding.TriageHint = "hardcoded_sentinel_error"
		return finding
	}

	entropy := scanner.ShannonEntropy(strVal)

	if hint, ok := matchShapeHeuristic(strVal, entropy); ok {
		finding.Severity = scanner.SeverityInfo
		finding.TriageHint = hint
		return finding
	}

	if upgraded, ok := applyEntropyGate(strVal, entropy); ok {
		finding.Severity = upgraded
		return finding
	}

	if constantsFilePattern.MatchString(finding.FilePath) {
		if finding.Severity == scanner.SeverityCritical {
			finding.Severity = scanner.SeverityHigh
		}
		finding.TriageHint = "crypto_key_constants_file"
		return finding
	}

	return finding
}

func isSentinelError(varName, strVal, initExpr string) bool {
	if initExpr == "errors.New" || initExpr == "fmt.Errorf" {
		return true
	}
	if errVarPattern.MatchString(varName) {
		lower := strings.ToLower(strVal)
		for _, word := range []string{"error", "fail", "invalid", "expired", "cannot", "unable", "missing", "denied", "unauthorized"} {
			if strings.Contains(lower, word) {
				return true
			}
		}
	}
	return false
}

func matchShapeHeuristic(strVal string, entropy float64) (string, bool) {
	if entropy >= 4.5 || len(strVal) > 40 {
		return "", false
	}
	if httpHeaderPrefixPattern.MatchString(strVal) {
		return "hardcoded_header_name", true
	}
	if snakeCasePattern.MatchString(strVal) {
		return "hardcoded_log_field", true
	}
	if len(strVal) <= 20 && filterCamelCasePattern.MatchString(strVal) {
		return "hardcoded_json_key", true
	}
	return "", false
}

func applyEntropyGate(strVal string, entropy float64) (scanner.Severity, bool) {
	if len(strVal) >= 32 && pureHexPattern.MatchString(strVal) {
		return scanner.SeverityCritical, true
	}
	if len(strVal) >= 24 && base64CharsetPattern.MatchString(strVal) && entropy >= 4.0 {
		return scanner.SeverityCritical, true
	}
	return "", false
}
