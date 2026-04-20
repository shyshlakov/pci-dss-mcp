package reportscanner

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
)

type ReportInput struct {
	Path         string `json:"path" jsonschema:"Path to the Go project to scan for PCI DSS compliance. If empty, uses current directory (.)"`
	DepScanMode  string `json:"dep_scan_mode,omitempty" jsonschema:"Dependency scanner mode: auto (default), online, offline. Controls network behavior for vulnerability checking"`
	IncludeTests bool   `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus"`
	IncludeTaint *bool  `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment via go/packages type analysis. When true, panscanner downgrades PAN-KEYWORD and suppresses PAN-TYPE findings for transit-only CHD fields (request/response DTOs, API client models) per and the PCI SSC FAQ on non-persistent memory. Adds 5-30 seconds to scan time. Default true (production-grade precision). Set false for fast dev iteration. Requires 'go' binary on PATH; falls back to AST-only scanning on failure."`
	MinSeverity  string `json:"min_severity,omitempty" jsonschema:"Filter findings by minimum severity. One of CRITICAL / HIGH / MEDIUM / LOW / INFO (case-insensitive). Default: no severity filter. Useful for AI clients that only need HIGH-or-above results."`
	RuleFilter   string `json:"rule_filter,omitempty" jsonschema:"Filter findings by rule ID. Comma-separated list for exact match (e.g. PAN-KEYWORD,PAN-TYPE) OR a single regex in leading/trailing slashes (e.g. /PAN-.*/). Default: no rule filter."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to return per call. Default 0 (summary-first response with next_cursor). To fetch more findings than fit in one response, follow next_cursor; do NOT raise this value to fetch all at once (server caps at the per-tool page size and rejects with LIMIT_EXCEEDS_PAGE_SIZE)."`
	Cursor       string `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior response. When set, resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
}

// ReportOutput is the discriminated sum type emitted by generate_compliance_report.
// Exactly one of Summary / Flat / Err is non-nil per call; the OutputSchema
// declared at registration time is a oneOf union so AI clients can discover the
// variant via the response_shape field.
type ReportOutput struct {
	Summary *SummaryResponse    `json:"summary,omitempty"`
	Flat    *FlatResponse       `json:"flat,omitempty"`
	Err     *CursorExpiredError `json:"error,omitempty"`
}

// FilterStats is preserved for backward compatibility with internal callers.
type FilterStats struct {
	Applied       bool   `json:"applied"`
	MinSeverity   string `json:"min_severity,omitempty"`
	RuleFilter    string `json:"rule_filter,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	OriginalCount int    `json:"original_count"`
	FilteredCount int    `json:"filtered_count"`
}

// RegisterTools registers the generate_compliance_report MCP tool with a
// oneOf OutputSchema union over SummaryResponse / FlatResponse /
// CursorExpiredError per CONTEXT D-04.
func RegisterTools(server *mcp.Server, db *pcidb.DB) {
	gen := NewReportGenerator(db)

	tool := &mcp.Tool{
		Name: "generate_compliance_report",
		Description: "Plain compliance report. For scan + AI triage + file:line enrichment " +
			"in a single call, prefer triage_findings - it is the recommended entry point " +
			"for interactive \"scan this project\" prompts. Use this tool when you need " +
			"audit-artifact output (requirement-level pass/fail without triage) or CI " +
			"pass/fail gates. " +
			"Run all PCI DSS v4.0.1 compliance scanners against a Go project and generate " +
			"a three-layer hybrid compliance report. Default unfiltered call returns a compact " +
			"summary (metadata, totals, requirement_statuses, top 20 findings per severity, and a " +
			"cursor for follow-up). Supply min_severity / rule_filter / limit to get a paged flat " +
			"list (60 per page with cursor), or cursor=<token> to resume a prior session " +
			"(10-minute TTL). Taint analysis is ON by default; set include_taint=false for " +
			"fast dev iteration.",
		Meta: mcp.Meta{"anthropic/maxResultSizeChars": 20000},
	}
	if schema, err := buildOutputSchemaUnion(); err == nil {
		tool.OutputSchema = schema
	} else {
		slog.Error("failed to build OutputSchema union", "err", err)
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, input ReportInput) (*mcp.CallToolResult, any, error) {
		path := strings.TrimSpace(input.Path)
		if path == "" {
			path = "."
		}
		input.Path = path

		if input.DepScanMode != "" && input.DepScanMode != "auto" && input.DepScanMode != "online" && input.DepScanMode != "offline" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"Invalid dep_scan_mode %q. Valid modes: auto, online, offline", input.DepScanMode)}},
				IsError: true,
			}, nil, nil
		}

		if input.Limit == -1 {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "LIMIT_MINUS_ONE_REMOVED: limit=-1 is no longer accepted. For interactive use, call with default params (summary-first with next_cursor) or apply min_severity/rule_filter for a paged flat response; follow the cursor for subsequent pages."}},
				IsError: true,
			}, nil, nil
		}

		if input.Limit > flatPageSize {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("LIMIT_EXCEEDS_PAGE_SIZE: limit=%d exceeds max=%d for generate_compliance_report. Use cursor pagination: call without limit (or with limit<=%d), then follow next_cursor for additional pages.", input.Limit, flatPageSize, flatPageSize)}},
				IsError: true,
			}, nil, nil
		}

		summary, flat, errResp, err := SelectAndExecute(ctx, gen, input, "generate_compliance_report")
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"generate_compliance_report error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		var text string
		var out any
		switch {
		case errResp != nil:
			out = errResp
			text = fmt.Sprintf("generate_compliance_report: %s (%s)", errResp.Code, errResp.Hint)
		case summary != nil:
			out = summary
			text = fmt.Sprintf("generate_compliance_report: summary (%d total findings, C=%d H=%d M=%d across %d scanners in %dms)",
				summary.Pagination.TotalFindings, summary.Summary.Critical, summary.Summary.High, summary.Summary.Medium,
				summary.Metadata.ScannerCount, summary.Metadata.DurationMS)
		case flat != nil:
			out = flat
			text = fmt.Sprintf("generate_compliance_report: flat (%d of %d findings returned, auto_capped=%t)",
				flat.Pagination.Returned, flat.Pagination.TotalFindings, flat.Pagination.AutoCapped)
		default:
			text = "generate_compliance_report: no response"
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: text}},
		}, out, nil
	})
}
