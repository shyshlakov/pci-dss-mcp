package triagescanner

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
)

// TriageInput is the input type for the triage_findings MCP tool.
//
// IncludeTaint mirrors ReportInput.IncludeTaint tri-state: nil → defaults
// to true (taint ON, production precision; matches generate_compliance_report
// default after flip); explicit false → taint OFF (fast dev iteration);
// explicit true → taint ON. Added in to close the behavioral mismatch
// between triage_findings and generate_compliance_report on the same codebase.
//
// adds three optional filter inputs (MinSeverity / RuleFilter / Limit)
// so AI clients can scope which findings are enriched. Filtering is applied
// BEFORE enrichment to save the per-finding context collection cost on
// findings the client does not care about.
type TriageInput struct {
	Path         string `json:"path" jsonschema:"Path to the Go project to triage. If empty, uses current directory (.)"`
	DepScanMode  string `json:"dep_scan_mode,omitempty" jsonschema:"Dependency scanner mode: auto (default), online, offline"`
	IncludeTests bool   `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false"`
	IncludeTaint *bool  `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment via go/packages type analysis. When true, panscanner downgrades PAN-KEYWORD and suppresses PAN-TYPE findings for transit-only CHD fields. Adds 5-30 seconds to scan time. Default true (production-grade precision, matches generate_compliance_report). Set false for fast dev iteration. Requires 'go' binary on PATH; falls back to AST-only scanning on failure."`
	MinSeverity  string `json:"min_severity,omitempty" jsonschema:"Filter findings by minimum severity. One of CRITICAL / HIGH / MEDIUM / LOW / INFO (case-insensitive). Default: no severity filter. Applied BEFORE enrichment to save context-collection cost."`
	RuleFilter   string `json:"rule_filter,omitempty" jsonschema:"Filter findings by rule ID. Comma-separated list for exact match (e.g. PAN-KEYWORD,PAN-TYPE) OR a single regex in leading/trailing slashes (e.g. /PAN-.*/). Default: no rule filter."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to enrich after filtering. Default 0 (unlimited). Use to cap triage cost on noisy projects."`
}

// RegisterTools registers the triage_findings MCP tool.
func RegisterTools(server *mcp.Server, db *pcidb.DB) {
	engine := NewTriageEngine()

	mcp.AddTool(server, &mcp.Tool{
		Name: "triage_findings",
		Description: "Collect contextual code evidence for PCI DSS compliance findings " +
			"to enable AI-assisted triage. Runs all scanners, then enriches each finding " +
			"with surrounding code, imports, middleware chains, router setup, and response " +
			"type evidence. Returns structured context so AI can classify findings as " +
			"confirmed, false positive, or needs manual review. Taint analysis is ON by " +
			"default (matches generate_compliance_report precision); set include_taint=false " +
			"for fast dev iteration.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TriageInput) (*mcp.CallToolResult, *TriageResult, error) {
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

		// tri-state: nil → true (production default matches
		// generate_compliance_report). Consumers that omit include_taint in
		// the MCP payload get the production-precision path; explicit false
		// preserves the legacy fast-dev path.
		includeTaint := true
		if input.IncludeTaint != nil {
			includeTaint = *input.IncludeTaint
		}

		// Run all scanners to get fresh findings.
		gen := reportscanner.NewReportGenerator(db)
		report, err := gen.GenerateWithOptions(ctx, path, input.DepScanMode, input.IncludeTests, includeTaint)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"triage_findings error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		// Extract active findings from report.
		var findings []scanner.Finding
		for _, rf := range report.Findings {
			findings = append(findings, rf.Finding)
		}

		// apply min_severity / rule_filter / limit BEFORE enrichment.
		// Filtering first avoids the per-finding context-collection cost on
		// findings the client does not care about.
		if input.MinSeverity != "" || input.RuleFilter != "" || input.Limit > 0 {
			filtered, ferr := reportscanner.FilterFindings(findings, input.MinSeverity, input.RuleFilter, input.Limit)
			if ferr != nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
						"rule_filter error: %s", ferr.Error())}},
					IsError: true,
				}, nil, nil
			}
			findings = filtered
		}

		if len(findings) == 0 {
			empty := &TriageResult{
				Findings: []EnrichedFinding{},
				Metadata: TriageMetadata{},
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "No active findings to triage. Project is clean."}},
			}, empty, nil
		}

		// Triage: enrich findings with context.
		result, err := engine.Triage(ctx, path, findings)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"triage error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		// pick ONE format per MCP spec and the "compact JSON only" convention.
		// Return a 1-line text summary for the human view and the
		// full TriageResult via the typed Out channel — the SDK marshals it
		// into CallToolResult.StructuredContent automatically. No hybrid
		// text+JSON dump, no per-finding pretty-printing.
		summary := fmt.Sprintf(
			"%d findings triaged in %dms (%d files analyzed). Structured results in tool output.",
			result.Metadata.FindingsTriaged,
			result.Metadata.DurationMS,
			result.Metadata.FilesAnalyzed,
		)

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, result, nil
	})
}
