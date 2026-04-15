package reportscanner

import (
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// severityRank converts a scanner.Severity to a numeric rank for "at least
// as severe as" comparisons. Higher number = more severe. Unknown severities
// rank at 0 so they never satisfy a threshold filter.
func severityRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 5
	case scanner.SeverityHigh:
		return 4
	case scanner.SeverityMedium:
		return 3
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 1
	}
	return 0
}

// severityFromString parses a case-insensitive severity name from an MCP
// tool input. Returns ok=false when the name is empty or unrecognized.
func severityFromString(name string) (scanner.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "":
		return "", false
	case "CRITICAL":
		return scanner.SeverityCritical, true
	case "HIGH":
		return scanner.SeverityHigh, true
	case "MEDIUM":
		return scanner.SeverityMedium, true
	case "LOW":
		return scanner.SeverityLow, true
	case "INFO":
		return scanner.SeverityInfo, true
	}
	return "", false
}

// FilterFindings applies min_severity, rule_filter, and limit to a slice of
// scanner.Finding. All parameters are optional and default to no-op:
//
// - minSeverity: empty string -> no severity threshold
// - ruleFilter: empty string -> no rule filter. Accepts comma-separated
// rule IDs (exact match) OR a single regex wrapped in leading/trailing
// slashes ("/PAN-.*/"). Regex form is detected by both leading and
// trailing '/'; otherwise the input is treated as a comma-list.
// - limit: 0 or negative -> unlimited
//
// Returns a new slice (never mutates input) so ordering + metadata on the
// caller's side is preserved. Returns an error only when ruleFilter contains
// an invalid regex.
func FilterFindings(findings []scanner.Finding, minSeverity, ruleFilter string, limit int) ([]scanner.Finding, error) {
	var minRank int
	if sev, ok := severityFromString(minSeverity); ok {
		minRank = severityRank(sev)
	}

	var ruleRE *regexp.Regexp
	var ruleSet map[string]bool
	if rf := strings.TrimSpace(ruleFilter); rf != "" {
		if len(rf) >= 2 && strings.HasPrefix(rf, "/") && strings.HasSuffix(rf, "/") {
			re, err := regexp.Compile(rf[1 : len(rf)-1])
			if err != nil {
				return nil, err
			}
			ruleRE = re
		} else {
			ruleSet = make(map[string]bool)
			for _, part := range strings.Split(rf, ",") {
				if id := strings.TrimSpace(part); id != "" {
					ruleSet[id] = true
				}
			}
		}
	}

	out := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		if minRank > 0 && severityRank(f.Severity) < minRank {
			continue
		}
		if ruleRE != nil && !ruleRE.MatchString(f.RuleID) {
			continue
		}
		if ruleSet != nil && !ruleSet[f.RuleID] {
			continue
		}
		out = append(out, f)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}
