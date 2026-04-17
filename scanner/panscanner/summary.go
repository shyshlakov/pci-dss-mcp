package panscanner

import (
	"sort"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityPAN = 3
const scannerNamePAN = "pan_data"
const hintPANSummary = "Call again with cursor to page through full findings, or use include_tests / exclude_patterns to narrow scope."

type PANSummaryResponse struct {
	ResponseShape string                       `json:"response_shape"`
	Scanner       string                       `json:"scanner"`
	Metadata      scanner.ScanMetadata         `json:"metadata"`
	Summary       PANSummaryCounts             `json:"summary"`
	TopFindings   map[string][]scanner.Finding `json:"top_findings"`
	Pagination    PANPaginationInfo            `json:"pagination"`
}

type PANSummaryCounts struct {
	BySeverity scanner.SeverityStats   `json:"by_severity"`
	ByRule     []PANRuleHistogramEntry `json:"by_rule"`
}

type PANRuleHistogramEntry struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

type PANPaginationInfo struct {
	TotalFindings int    `json:"total_findings"`
	Returned      int    `json:"returned"`
	NextCursor    string `json:"next_cursor,omitempty"`
	Hint          string `json:"hint"`
}

type PANCursorError struct {
	ResponseShape string `json:"response_shape"`
	Error         string `json:"error"`
	Code          string `json:"code"`
	Hint          string `json:"hint"`
}

func severityKeyPAN(s scanner.Severity) string {
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

func pickTopNPAN(findings []scanner.Finding, severityKey string, n int) []scanner.Finding {
	matches := make([]scanner.Finding, 0, n*2)
	for _, f := range findings {
		if severityKeyPAN(f.Severity) == severityKey {
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

func buildPANSummaryInternal(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *PANSummaryResponse {
	counts := scanner.CountBySeverity(findings)
	ruleCounts := map[string]int{}
	for _, f := range findings {
		ruleCounts[f.RuleID]++
	}
	hist := make([]PANRuleHistogramEntry, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		hist = append(hist, PANRuleHistogramEntry{RuleID: r, Count: c})
	}
	sort.SliceStable(hist, func(i, j int) bool {
		if hist[i].Count != hist[j].Count {
			return hist[i].Count > hist[j].Count
		}
		return hist[i].RuleID < hist[j].RuleID
	})
	top := map[string][]scanner.Finding{
		"critical": pickTopNPAN(findings, "critical", TopNPerSeverityPAN),
		"high":     pickTopNPAN(findings, "high", TopNPerSeverityPAN),
		"medium":   pickTopNPAN(findings, "medium", TopNPerSeverityPAN),
		"low":      pickTopNPAN(findings, "low", TopNPerSeverityPAN),
		"info":     pickTopNPAN(findings, "info", TopNPerSeverityPAN),
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
	return &PANSummaryResponse{
		ResponseShape: "summary",
		Scanner:       scannerNamePAN,
		Metadata: scanner.ScanMetadata{
			ScannedFiles: meta.TotalFiles,
			ScannedLines: meta.TotalLines,
			DurationMS:   meta.DurationMS,
		},
		Summary: PANSummaryCounts{
			BySeverity: scanner.SeverityStats{
				Critical: counts[scanner.SeverityCritical],
				High:     counts[scanner.SeverityHigh],
				Medium:   counts[scanner.SeverityMedium],
				Low:      counts[scanner.SeverityLow],
				Info:     counts[scanner.SeverityInfo],
			},
			ByRule: hist,
		},
		TopFindings: top,
		Pagination: PANPaginationInfo{
			TotalFindings: len(findings),
			Returned:      returned,
			NextCursor:    nextCursor,
			Hint:          hintPANSummary,
		},
	}
}
