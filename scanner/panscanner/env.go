package panscanner

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// scanEnvFile parses a.env file and detects hardcoded PANs and sensitive key names.
// Returns findings, line count, and error.
//
// Detection rules:
// - PAN-LITERAL: Value contains a Luhn+IIN valid card number -> CRITICAL
// - PAN-KEYWORD: Key name matches sensitive keyword with non-empty value -> HIGH
func scanEnvFile(path string) ([]scanner.Finding, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close env file", "path", path, "err", cerr)
		}
	}()

	var findings []scanner.Finding
	lineNum := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Skip empty lines and comments.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Split on first '=' to get key and value.
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:eqIdx])
		value := strings.TrimSpace(trimmed[eqIdx+1:])

		// Strip surrounding quotes from value.
		value = stripQuotes(value)

		keyIsSensitive := IsSensitiveKeyword(key)

		// Extract digits from value for PAN check.
		digits := ExtractDigits(value)
		if len(digits) >= 13 && len(digits) <= 19 && IsLikelyPAN(digits) {
			desc := "Hardcoded card number detected in .env file"
			if keyIsSensitive {
				desc = "Hardcoded card number in .env file with sensitive key name"
			}
			findings = append(findings, scanner.Finding{
				RuleID:        "PAN-LITERAL",
				Severity:      scanner.SeverityCritical,
				RequirementID: "3.4.1",
				FilePath:      path,
				Line:          lineNum,
				Description:   desc,
				Suggestion:    "Remove card number from config. Use tokenized references or vault-managed secrets.",
			})
		}

		// If key is sensitive and value is non-empty, flag even without valid PAN.
		if keyIsSensitive && value != "" {
			// Only add this if we didn't already add a PAN-LITERAL finding.
			alreadyHasPANLiteral := false
			for _, f := range findings {
				if f.Line == lineNum && f.RuleID == "PAN-LITERAL" {
					alreadyHasPANLiteral = true
					break
				}
			}
			findings = append(findings, scanner.Finding{
				RuleID:        "PAN-KEYWORD",
				Severity:      scanner.SeverityHigh,
				RequirementID: "3.3.1",
				FilePath:      path,
				Line:          lineNum,
				Description: func() string {
					if alreadyHasPANLiteral {
						return fmt.Sprintf("Potentially sensitive data in .env file key '%s' contains card number", key)
					}
					return fmt.Sprintf("Potentially sensitive data in .env file key '%s'", key)
				}(),
				Suggestion:          "Use vault-managed secrets or environment injection instead of .env files for sensitive data.",
				RelatedRequirements: []string{"3.3.1.2"},
			})
		}
	}

	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", path, err)
	}

	return findings, lineNum, nil
}

// stripQuotes removes surrounding double or single quotes from a string.
func stripQuotes(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
