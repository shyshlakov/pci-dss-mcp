package triagescanner

import (
	"sort"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityTriage = 2

const hintTriageSummary = "Call again with cursor to page through full enriched findings, or use min_severity / rule_filter to narrow."

type TriageSummaryResponse struct {
	ResponseShape string                       `json:"response_shape"`
	Metadata      TriageLayerBMetadata         `json:"metadata"`
	Summary       TriageSummaryCounts          `json:"summary"`
	TopFindings   map[string][]EnrichedFinding `json:"top_findings"`
	Pagination    TriagePaginationInfo         `json:"pagination"`
}

type TriageLayerBMetadata struct {
	FindingsTotal   int   `json:"findings_total"`
	FindingsTriaged int   `json:"findings_triaged"`
	FilesAnalyzed   int   `json:"files_analyzed"`
	DurationMS      int64 `json:"duration_ms"`
}

type TriageSummaryCounts struct {
	BySeverity map[string]int       `json:"by_severity"`
	ByRule     []RuleHistogramEntry `json:"by_rule"`
}

type RuleHistogramEntry struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

type TriagePaginationInfo struct {
	TotalFindings int    `json:"total_findings"`
	Returned      int    `json:"returned"`
	NextCursor    string `json:"next_cursor,omitempty"`
	Hint          string `json:"hint"`
}

type TriageCursorError struct {
	ResponseShape string `json:"response_shape"`
	Error         string `json:"error"`
	Code          string `json:"code"`
	Hint          string `json:"hint"`
}

func severityKey(s scanner.Severity) string {
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

func severityTriage(ef EnrichedFinding) string {
	return severityKey(ef.Finding.Severity)
}

func pickTopNTriage(enriched []EnrichedFinding, severityKey string, n int) []EnrichedFinding {
	matches := make([]EnrichedFinding, 0, n*2)
	for _, ef := range enriched {
		if severityTriage(ef) == severityKey {
			matches = append(matches, ef)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Finding.RuleID != matches[j].Finding.RuleID {
			return matches[i].Finding.RuleID < matches[j].Finding.RuleID
		}
		return matches[i].Finding.FilePath < matches[j].Finding.FilePath
	})
	if len(matches) > n {
		matches = matches[:n]
	}
	return matches
}

func buildTriageSummaryInternal(
	enriched []EnrichedFinding,
	layerBMeta TriageLayerBMetadata,
	cacheMeta hybridcache.ScanMeta,
	totalFindings int,
	sid, nextCursor string,
) *TriageSummaryResponse {
	bySev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	ruleCounts := map[string]int{}
	for _, ef := range enriched {
		bySev[severityTriage(ef)]++
		ruleCounts[ef.Finding.RuleID]++
	}
	hist := make([]RuleHistogramEntry, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		hist = append(hist, RuleHistogramEntry{RuleID: r, Count: c})
	}
	sort.SliceStable(hist, func(i, j int) bool {
		if hist[i].Count != hist[j].Count {
			return hist[i].Count > hist[j].Count
		}
		return hist[i].RuleID < hist[j].RuleID
	})
	top := map[string][]EnrichedFinding{
		"critical": pickTopNTriage(enriched, "critical", TopNPerSeverityTriage),
		"high":     pickTopNTriage(enriched, "high", TopNPerSeverityTriage),
		"medium":   pickTopNTriage(enriched, "medium", TopNPerSeverityTriage),
		"low":      pickTopNTriage(enriched, "low", TopNPerSeverityTriage),
		"info":     pickTopNTriage(enriched, "info", TopNPerSeverityTriage),
	}
	returned := 0
	for _, v := range top {
		returned += len(v)
	}
	return &TriageSummaryResponse{
		ResponseShape: "summary",
		Metadata:      layerBMeta,
		Summary: TriageSummaryCounts{
			BySeverity: bySev,
			ByRule:     hist,
		},
		TopFindings: top,
		Pagination: TriagePaginationInfo{
			TotalFindings: totalFindings,
			Returned:      returned,
			NextCursor:    nextCursor,
			Hint:          hintTriageSummary,
		},
	}
}
