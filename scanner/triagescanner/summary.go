package triagescanner

import (
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityTriage = 2

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

func buildTriageSummaryInternal(
	enriched []EnrichedFinding,
	layerBMeta TriageLayerBMetadata,
	cacheMeta hybridcache.ScanMeta,
	totalFindings int,
	sid, nextCursor string,
) *TriageSummaryResponse {
	return nil
}

func pickTopNTriage(findings []EnrichedFinding, severityKey string, n int) []EnrichedFinding {
	return nil
}
