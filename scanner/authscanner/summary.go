package authscanner

import (
	"sort"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityAuth = 3
const MaxByRuleEntries = 10
const scannerNameAuth = "auth_strength"
const hintAuthSummary = "Call again with cursor to page through full findings, or use min_severity / rule_filter to narrow scope."

type AuthSummaryResponse struct {
	ResponseShape string                       `json:"response_shape"`
	Scanner       string                       `json:"scanner"`
	Metadata      scanner.ScanMetadata         `json:"metadata"`
	Summary       AuthSummaryCounts            `json:"summary"`
	TopFindings   map[string][]scanner.Finding `json:"top_findings"`
	Pagination    AuthPaginationInfo           `json:"pagination"`
}

type AuthSummaryCounts struct {
	BySeverity scanner.SeverityStats    `json:"by_severity"`
	ByRule     []AuthRuleHistogramEntry `json:"by_rule"`
	MoreRules  int                      `json:"more_rules,omitempty"`
}

type AuthRuleHistogramEntry struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

type AuthPaginationInfo struct {
	TotalFindings int    `json:"total_findings"`
	Returned      int    `json:"returned"`
	NextCursor    string `json:"next_cursor,omitempty"`
	Hint          string `json:"hint"`
}

type AuthCursorError struct {
	ResponseShape string `json:"response_shape"`
	Error         string `json:"error"`
	Code          string `json:"code"`
	Hint          string `json:"hint"`
}

func severityKeyAuth(s scanner.Severity) string {
	switch s {
	case scanner.SeverityCritical:
		return "critical"
	case scanner.SeverityHigh:
		return "high"
	case scanner.SeverityMedium:
		return "medium"
	case scanner.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func pickTopNAuth(findings []scanner.Finding, severityKey string, n int) []scanner.Finding {
	matches := make([]scanner.Finding, 0, n*2)
	for _, f := range findings {
		if severityKeyAuth(f.Severity) == severityKey {
			matches = append(matches, f)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].RuleID != matches[j].RuleID {
			return matches[i].RuleID < matches[j].RuleID
		}
		return matches[i].FilePath < matches[j].FilePath
	})
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

func buildAuthSummaryInternal(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *AuthSummaryResponse {
	counts := scanner.CountBySeverity(findings)
	ruleCounts := map[string]int{}
	for _, f := range findings {
		ruleCounts[f.RuleID]++
	}
	hist := make([]AuthRuleHistogramEntry, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		hist = append(hist, AuthRuleHistogramEntry{RuleID: r, Count: c})
	}
	sort.SliceStable(hist, func(i, j int) bool {
		if hist[i].Count != hist[j].Count {
			return hist[i].Count > hist[j].Count
		}
		return hist[i].RuleID < hist[j].RuleID
	})
	moreRules := 0
	if len(hist) > MaxByRuleEntries {
		moreRules = len(hist) - MaxByRuleEntries
		hist = hist[:MaxByRuleEntries]
	}
	top := map[string][]scanner.Finding{
		"critical": pickTopNAuth(findings, "critical", TopNPerSeverityAuth),
		"high":     pickTopNAuth(findings, "high", TopNPerSeverityAuth),
		"medium":   pickTopNAuth(findings, "medium", TopNPerSeverityAuth),
		"low":      pickTopNAuth(findings, "low", TopNPerSeverityAuth),
		"info":     pickTopNAuth(findings, "info", TopNPerSeverityAuth),
	}
	for k, v := range top {
		if v == nil {
			top[k] = []scanner.Finding{}
		}
	}
	returned := 0
	for _, v := range top {
		returned += len(v)
	}
	return &AuthSummaryResponse{
		ResponseShape: "summary",
		Scanner:       scannerNameAuth,
		Metadata: scanner.ScanMetadata{
			ScannedFiles: meta.TotalFiles,
			ScannedLines: meta.TotalLines,
			DurationMS:   meta.DurationMS,
		},
		Summary: AuthSummaryCounts{
			BySeverity: scanner.SeverityStats{
				Critical: counts[scanner.SeverityCritical],
				High:     counts[scanner.SeverityHigh],
				Medium:   counts[scanner.SeverityMedium],
				Low:      counts[scanner.SeverityLow],
				Info:     counts[scanner.SeverityInfo],
			},
			ByRule:    hist,
			MoreRules: moreRules,
		},
		TopFindings: top,
		Pagination: AuthPaginationInfo{
			TotalFindings: len(findings),
			Returned:      returned,
			NextCursor:    nextCursor,
			Hint:          hintAuthSummary,
		},
	}
}
