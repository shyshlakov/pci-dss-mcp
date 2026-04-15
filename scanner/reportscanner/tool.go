package reportscanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CompactReport is a slim version of ComplianceReport for MCP tool output.
// Strips not_checked (static PCI DSS spec, 234 items), findings_by_rule
// (duplicate of findings), and NOT_CHECKED entries from requirement_status.
// This reduces output from ~210KB to ~40KB, fitting within MCP token limits.
type CompactReport struct {
	Metadata          ReportMetadata               `json:"metadata"`
	Summary           ReportSummary                `json:"summary"`
	ScanSummary       *ScanSummary                 `json:"scan_summary,omitempty"`
	RequirementStatus map[string]RequirementStatus `json:"requirement_status"`
	Findings          []ReportFinding              `json:"findings"`
	Suppressions      []SuppressionEntry           `json:"suppressions"`
}

// compactReportForMCP converts a full ComplianceReport to a compact version
// suitable for MCP tool output. Filters requirement_status to only include
// checked requirements (PASS/FAIL/WARNING/SUPPRESSED), dropping NOT_CHECKED.
func compactReportForMCP(r *ComplianceReport) *CompactReport {
	checked := make(map[string]RequirementStatus, len(r.RequirementStatus))
	for id, rs := range r.RequirementStatus {
		if rs.Status != "NOT_CHECKED" {
			checked[id] = rs
		}
	}
	return &CompactReport{
		Metadata:          r.Metadata,
		Summary:           r.Summary,
		ScanSummary:       r.ScanSummary,
		RequirementStatus: checked,
		Findings:          r.Findings,
		Suppressions:      r.Suppressions,
	}
}

// ReportInput is the input type for the generate_compliance_report MCP tool.
//
// IncludeTaint is a pointer (tri-state) to distinguish three cases:
// - nil (field omitted in JSON) → defaults to true (taint ON, production precision)
// - explicit false → taint OFF (fast dev iteration)
// - explicit true → taint ON (no-op, matches default)
//
// This preserves backward compat for MCP consumers that pass
// include_taint=false AND establishes taint-ON as the safer production default
// for consumers that omit the field.
//
// adds three optional filter inputs (MinSeverity / RuleFilter / Limit)
// so AI clients can scope the report before it crosses the MCP boundary.
// Filtering is applied BEFORE serialization to keep the response small.
type ReportInput struct {
	Path         string `json:"path" jsonschema:"Path to the Go project to scan for PCI DSS compliance. If empty, uses current directory (.)"`
	DepScanMode  string `json:"dep_scan_mode,omitempty" jsonschema:"Dependency scanner mode: auto (default), online, offline. Controls network behavior for vulnerability checking"`
	IncludeTests bool   `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus"`
	IncludeTaint *bool  `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment via go/packages type analysis. When true, panscanner downgrades PAN-KEYWORD and suppresses PAN-TYPE findings for transit-only CHD fields (request/response DTOs, API client models) per and the PCI SSC FAQ on non-persistent memory. Adds 5-30 seconds to scan time. Default true (production-grade precision). Set false for fast dev iteration. Requires 'go' binary on PATH; falls back to AST-only scanning on failure."`
	MinSeverity  string `json:"min_severity,omitempty" jsonschema:"Filter findings by minimum severity. One of CRITICAL / HIGH / MEDIUM / LOW / INFO (case-insensitive). Default: no severity filter. Useful for AI clients that only need HIGH-or-above results."`
	RuleFilter   string `json:"rule_filter,omitempty" jsonschema:"Filter findings by rule ID. Comma-separated list for exact match (e.g. PAN-KEYWORD,PAN-TYPE) OR a single regex in leading/trailing slashes (e.g. /PAN-.*/). Default: no rule filter."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to return after filtering. Default 0 (unlimited). Use to cap response size on noisy projects."`
}

// ReportOutput is the typed MCP output for generate_compliance_report. The
// MCP SDK auto-infers OutputSchema from the struct tags. Compact
// form is used to keep the response under MCP token limits; filter stats
// are included when any filter parameter is supplied.
type ReportOutput struct {
	Report           *CompactReport `json:"report" jsonschema:"Compact compliance report (metadata, summary, requirement_status for checked requirements, findings, suppressions)"`
	ComplianceStatus string         `json:"compliance_status" jsonschema:"PASS when no CRITICAL/HIGH/MEDIUM findings remain after filtering; FAIL otherwise"`
	ActiveFindings   int            `json:"active_findings" jsonschema:"Number of CRITICAL+HIGH+MEDIUM findings in the filtered report"`
	Filtered         *FilterStats   `json:"filtered,omitempty" jsonschema:"Filter statistics when min_severity / rule_filter / limit were applied"`
}

// FilterStats documents how filter parameters scoped a report response.
type FilterStats struct {
	Applied       bool   `json:"applied"`
	MinSeverity   string `json:"min_severity,omitempty"`
	RuleFilter    string `json:"rule_filter,omitempty"`
	Limit         int    `json:"limit,omitempty"`
	OriginalCount int    `json:"original_count"`
	FilteredCount int    `json:"filtered_count"`
}

// RegisterTools registers the generate_compliance_report MCP tool.
func RegisterTools(server *mcp.Server, db *pcidb.DB) {
	gen := NewReportGenerator(db)

	mcp.AddTool(server, &mcp.Tool{
		Name: "generate_compliance_report",
		Description: "Run all PCI DSS v4.0.1 compliance scanners against a Go project and generate " +
			"a compliance report. Checks 16 PCI DSS requirements across 11 scanners: PAN data " +
			"exposure, encryption, TLS, secrets, error handling, authentication, audit logging, " +
			"data retention, payment page scripts, SQL schema, and dependency vulnerabilities. Returns " +
			"structured output with metadata, summary, checked requirement statuses (PASS/FAIL/SUPPRESSED), " +
			"and findings array. Supports optional min_severity / rule_filter / limit filter parameters " +
			"for AI clients that need to scope responses. Taint analysis is ON by default (production-grade " +
			"precision); set include_taint=false for fast dev iteration (adds 5-30s otherwise). Use " +
			"FormatHumanReadable() for terminal output.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ReportInput) (*mcp.CallToolResult, *ReportOutput, error) {
		path := strings.TrimSpace(input.Path)
		if path == "" {
			path = "."
		}

		// Validate dep_scan_mode if provided.
		if input.DepScanMode != "" && input.DepScanMode != "auto" && input.DepScanMode != "online" && input.DepScanMode != "offline" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"Invalid dep_scan_mode %q. Valid modes: auto, online, offline", input.DepScanMode)}},
				IsError: true,
			}, nil, nil
		}

		// tri-state: nil → true (production default); explicit value
		// preserved. Omitted include_taint in the MCP payload means the
		// consumer wants the production-precision path.
		includeTaint := true
		if input.IncludeTaint != nil {
			includeTaint = *input.IncludeTaint
		}

		report, err := gen.GenerateWithOptions(ctx, path, input.DepScanMode, input.IncludeTests, includeTaint)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"generate_compliance_report error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		// apply min_severity / rule_filter / limit before serialization.
		var filterStats *FilterStats
		if input.MinSeverity != "" || input.RuleFilter != "" || input.Limit > 0 {
			raw := make([]scanner.Finding, 0, len(report.Findings))
			for _, rf := range report.Findings {
				raw = append(raw, rf.Finding)
			}
			filtered, ferr := FilterFindings(raw, input.MinSeverity, input.RuleFilter, input.Limit)
			if ferr != nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
						"rule_filter error: %s", ferr.Error())}},
					IsError: true,
				}, nil, nil
			}
			// Project filtered back onto ReportFinding slice to preserve
			// per-finding requirement_title / scanner_name metadata. Key on
			// rule+path+line so duplicates at the same site still match.
			kept := make(map[string]bool, len(filtered))
			for _, f := range filtered {
				kept[f.RuleID+"#"+f.FilePath+"#"+fmt.Sprint(f.Line)] = true
			}
			originalCount := len(report.Findings)
			trimmed := make([]ReportFinding, 0, len(filtered))
			for _, rf := range report.Findings {
				key := rf.RuleID + "#" + rf.FilePath + "#" + fmt.Sprint(rf.Line)
				if kept[key] {
					trimmed = append(trimmed, rf)
					if input.Limit > 0 && len(trimmed) >= input.Limit {
						break
					}
				}
			}
			report.Findings = trimmed
			// Recompute severity summary after filtering so the compliance
			// status reflects the scoped view (not the pre-filter totals).
			report.Summary.Critical = 0
			report.Summary.High = 0
			report.Summary.Medium = 0
			report.Summary.Low = 0
			report.Summary.Info = 0
			for _, rf := range report.Findings {
				switch rf.Severity {
				case scanner.SeverityCritical:
					report.Summary.Critical++
				case scanner.SeverityHigh:
					report.Summary.High++
				case scanner.SeverityMedium:
					report.Summary.Medium++
				case scanner.SeverityLow:
					report.Summary.Low++
				case scanner.SeverityInfo:
					report.Summary.Info++
				}
			}
			filterStats = &FilterStats{
				Applied:       true,
				MinSeverity:   input.MinSeverity,
				RuleFilter:    input.RuleFilter,
				Limit:         input.Limit,
				OriginalCount: originalCount,
				FilteredCount: len(trimmed),
			}
		}

		// Build compact report + typed output.
		compact := compactReportForMCP(report)

		activeCount := report.Summary.Critical + report.Summary.High + report.Summary.Medium
		complianceStatus := "PASS"
		if activeCount > 0 {
			complianceStatus = "FAIL"
		}

		out := &ReportOutput{
			Report:           compact,
			ComplianceStatus: complianceStatus,
			ActiveFindings:   activeCount,
			Filtered:         filterStats,
		}

		summary := fmt.Sprintf("generate_compliance_report: %s (%d active findings across %d scanners in %dms)",
			complianceStatus, activeCount, report.Metadata.ScannerCount, report.Metadata.DurationMS)

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
