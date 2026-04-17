package panscanner

import (
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const TopNPerSeverityPAN = 3

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

func buildPANSummaryInternal(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *PANSummaryResponse {
	return nil
}

func pickTopNPAN(findings []scanner.Finding, severityKey string, n int) []scanner.Finding {
	return nil
}
