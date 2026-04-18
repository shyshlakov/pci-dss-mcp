package scriptscanner

import (
	"sort"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityScript = 3
const MaxByRuleEntries = 10
const scannerNameScript = "payment_page_scripts"
const hintScriptSummary = "Call again with cursor to page through full findings, or use min_severity / rule_filter to narrow scope."

type ScriptSummaryResponse struct {
	ResponseShape string                       `json:"response_shape"`
	Scanner       string                       `json:"scanner"`
	Metadata      scanner.ScanMetadata         `json:"metadata"`
	Summary       ScriptSummaryCounts          `json:"summary"`
	TopFindings   map[string][]scanner.Finding `json:"top_findings"`
	Pagination    ScriptPaginationInfo         `json:"pagination"`
}

type ScriptSummaryCounts struct {
	BySeverity scanner.SeverityStats      `json:"by_severity"`
	ByRule     []ScriptRuleHistogramEntry `json:"by_rule"`
	MoreRules  int                        `json:"more_rules,omitempty"`
}

type ScriptRuleHistogramEntry struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

type ScriptPaginationInfo struct {
	TotalFindings int    `json:"total_findings"`
	Returned      int    `json:"returned"`
	NextCursor    string `json:"next_cursor,omitempty"`
	Hint          string `json:"hint"`
}

type ScriptCursorError struct {
	ResponseShape string `json:"response_shape"`
	Error         string `json:"error"`
	Code          string `json:"code"`
	Hint          string `json:"hint"`
}

func severityKeyScript(s scanner.Severity) string {
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

func pickTopNScript(findings []scanner.Finding, severityKey string, n int) []scanner.Finding {
	matches := make([]scanner.Finding, 0, n*2)
	for _, f := range findings {
		if severityKeyScript(f.Severity) == severityKey {
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

func buildScriptSummaryInternal(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *ScriptSummaryResponse {
	counts := scanner.CountBySeverity(findings)
	ruleCounts := map[string]int{}
	for _, f := range findings {
		ruleCounts[f.RuleID]++
	}
	hist := make([]ScriptRuleHistogramEntry, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		hist = append(hist, ScriptRuleHistogramEntry{RuleID: r, Count: c})
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
		"critical": pickTopNScript(findings, "critical", TopNPerSeverityScript),
		"high":     pickTopNScript(findings, "high", TopNPerSeverityScript),
		"medium":   pickTopNScript(findings, "medium", TopNPerSeverityScript),
		"low":      pickTopNScript(findings, "low", TopNPerSeverityScript),
		"info":     pickTopNScript(findings, "info", TopNPerSeverityScript),
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
	return &ScriptSummaryResponse{
		ResponseShape: "summary",
		Scanner:       scannerNameScript,
		Metadata: scanner.ScanMetadata{
			ScannedFiles: meta.TotalFiles,
			ScannedLines: meta.TotalLines,
			DurationMS:   meta.DurationMS,
		},
		Summary: ScriptSummaryCounts{
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
		Pagination: ScriptPaginationInfo{
			TotalFindings: len(findings),
			Returned:      returned,
			NextCursor:    nextCursor,
			Hint:          hintScriptSummary,
		},
	}
}
