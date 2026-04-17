package triagescanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybrid"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
)

const toolNameTriage = "triage_findings"

type TriageInput struct {
	Path         string `json:"path" jsonschema:"Path to the Go project to triage. If empty, uses current directory (.)"`
	DepScanMode  string `json:"dep_scan_mode,omitempty" jsonschema:"Dependency scanner mode: auto (default), online, offline"`
	IncludeTests bool   `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false"`
	IncludeTaint *bool  `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment via go/packages type analysis. When true, panscanner downgrades PAN-KEYWORD and suppresses PAN-TYPE findings for transit-only CHD fields. Adds 5-30 seconds to scan time. Default true (production-grade precision, matches generate_compliance_report). Set false for fast dev iteration. Requires 'go' binary on PATH; falls back to AST-only scanning on failure."`
	MinSeverity  string `json:"min_severity,omitempty" jsonschema:"Filter findings by minimum severity. One of CRITICAL / HIGH / MEDIUM / LOW / INFO (case-insensitive). Default: no severity filter. Applied BEFORE enrichment to save context-collection cost."`
	RuleFilter   string `json:"rule_filter,omitempty" jsonschema:"Filter findings by rule ID. Comma-separated list for exact match (e.g. PAN-KEYWORD,PAN-TYPE) OR a single regex in leading/trailing slashes (e.g. /PAN-.*/). Default: no rule filter."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to enrich after filtering. Default 0 (unlimited). Use to cap triage cost on noisy projects. Pass -1 for a full flat response (auto-capped at 500)."`
	Cursor       string `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior triage_findings response. When set, resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
}

type triageCacher struct{}

func (triageCacher) Put(sid string, findings []scanner.Finding, meta hybridcache.ScanMeta) {
	cp := make([]scanner.Finding, len(findings))
	copy(cp, findings)
	hybridcache.Put(sid, &hybridcache.Entry{Findings: cp, Meta: meta})
}

func (triageCacher) Get(sid string) ([]scanner.Finding, hybridcache.ScanMeta, bool) {
	entry, ok := hybridcache.Get(sid)
	if !ok {
		return nil, hybridcache.ScanMeta{}, false
	}
	return entry.Findings, entry.Meta, true
}

func RegisterTools(server *mcp.Server, db *pcidb.DB) {
	engine := NewTriageEngine()
	schema, schemaErr := buildTriageOutputSchemaUnion()
	if schemaErr != nil {
		slog.Warn("buildTriageOutputSchemaUnion failed", "err", schemaErr)
	}

	tool := &mcp.Tool{
		Name: toolNameTriage,
		Description: "RECOMMENDED entry point for \"scan this project\" prompts - runs all " +
			"PCI DSS v4.0.1 compliance scanners AND applies AI-assisted prioritization " +
			"+ file:line enrichment in a single call. You do NOT need to call " +
			"generate_compliance_report separately; this tool already runs the same " +
			"scanner pipeline. Use generate_compliance_report only when you need a plain " +
			"compliance report without triage (audit artifacts, CI pass/fail gates). " +
			"Default: returns response_shape \"summary\" with by_severity counts, a " +
			"capped by_rule histogram (top 10 + more_rules), and top 1 per severity " +
			"enriched finding - plus a pagination.next_cursor for drill-down. " +
			"Follow the cursor for the full enriched list. " +
			"limit: -1 is an advanced escape hatch that can return >100 KB of JSON; " +
			"use only for CI/batch pipelines, not interactive UX. " +
			"Apply min_severity / rule_filter for a filtered flat response.",
		Meta:         mcp.Meta{"anthropic/maxResultSizeChars": 20000},
		OutputSchema: json.RawMessage(schema),
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, input TriageInput) (*mcp.CallToolResult, any, error) {
		path := strings.TrimSpace(input.Path)
		if path == "" {
			path = "."
		}
		if input.DepScanMode != "" && input.DepScanMode != "auto" && input.DepScanMode != "online" && input.DepScanMode != "offline" {
			return triageErrorResult(fmt.Sprintf("Invalid dep_scan_mode %q. Valid modes: auto, online, offline", input.DepScanMode)), nil, nil
		}
		if input.Cursor != "" {
			if input.MinSeverity != "" || input.RuleFilter != "" || input.Limit > 0 || input.IncludeTests || input.DepScanMode != "" || input.IncludeTaint != nil {
				return triageErrorResult("triage_findings cursor_malformed: cursor + filter/scope params is not supported; re-run without cursor to apply new filters"), nil, nil
			}
		}
		includeTaint := true
		if input.IncludeTaint != nil {
			includeTaint = *input.IncludeTaint
		}
		absPath, aerr := filepath.Abs(filepath.Clean(path))
		if aerr != nil {
			absPath = path
		}
		scanTS := time.Now().UTC().Format(time.RFC3339)

		scan := func(ctx context.Context, in hybrid.Input) ([]scanner.Finding, hybridcache.ScanMeta, error) {
			gen := reportscanner.NewReportGenerator(db)
			report, err := gen.GenerateWithOptions(ctx, path, input.DepScanMode, input.IncludeTests, includeTaint)
			if err != nil {
				return nil, hybridcache.ScanMeta{}, err
			}
			out := make([]scanner.Finding, 0, len(report.Findings))
			for _, rf := range report.Findings {
				out = append(out, rf.Finding)
			}
			meta := hybridcache.ScanMeta{
				TotalFiles: report.Metadata.TotalFiles,
				TotalLines: report.Metadata.TotalLines,
				DurationMS: report.Metadata.DurationMS,
			}
			return out, meta, nil
		}

		filterFn := func(findings []scanner.Finding, minSev, ruleFilter string) ([]scanner.Finding, error) {
			return reportscanner.FilterFindings(findings, minSev, ruleFilter, 0)
		}

		buildSummary := func(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *TriageSummaryResponse {
			total := len(findings)
			result, terr := engine.Triage(ctx, path, findings)
			if terr != nil {
				slog.Warn("triage enrichment failed inside buildSummary", "err", terr)
				return buildTriageSummaryInternal(nil, TriageLayerBMetadata{FindingsTotal: total}, meta, total, sid, nextCursor)
			}
			layerBMeta := TriageLayerBMetadata{
				FindingsTotal:   total,
				FindingsTriaged: result.Metadata.FindingsTriaged,
				FilesAnalyzed:   result.Metadata.FilesAnalyzed,
				DurationMS:      result.Metadata.DurationMS,
			}
			return buildTriageSummaryInternal(result.Findings, layerBMeta, meta, total, sid, nextCursor)
		}

		buildFlat := func(findings []scanner.Finding, off, pageSize, total int, meta hybridcache.ScanMeta, sid, nextCursor string, autoCapped bool) *TriageResult {
			result, terr := engine.Triage(ctx, path, findings)
			if terr != nil {
				slog.Warn("triage enrichment failed inside buildFlat", "err", terr)
				return &TriageResult{ResponseShape: "flat", Findings: []EnrichedFinding{}}
			}
			result.ResponseShape = "flat"
			result.Metadata.FindingsTotal = total
			if nextCursor != "" {
				result.NextCursor = nextCursor
			}
			return result
		}

		in := hybrid.Input{
			AbsPath:       absPath,
			Cursor:        input.Cursor,
			MinSeverity:   input.MinSeverity,
			RuleFilter:    input.RuleFilter,
			Limit:         input.Limit,
			IncludeTests:  input.IncludeTests,
			IncludeTaint:  includeTaint,
			ScanTimestamp: scanTS,
			ToolName:      toolNameTriage,
		}
		res, err := hybrid.SelectAndExecute[scanner.Finding, TriageSummaryResponse, TriageResult](
			ctx, in, scan, filterFn, buildSummary, buildFlat, triageCacher{},
		)
		if err != nil {
			return triageErrorResult(fmt.Sprintf("triage_findings error: %s", err.Error())), nil, nil
		}
		if res.Err != nil {
			cerr := &TriageCursorError{
				ResponseShape: "error",
				Error:         strings.ToLower(res.Err.Code),
				Code:          res.Err.Code,
				Hint:          res.Err.Hint,
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: res.Err.Code}},
				IsError: true,
			}, cerr, nil
		}
		if res.Summary != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage_findings: %d findings analyzed (summary with top %d per severity)", res.Summary.Pagination.TotalFindings, TopNPerSeverityTriage)}},
			}, res.Summary, nil
		}
		if res.Flat == nil {
			return triageErrorResult("triage_findings: enrichment failed (context cancelled or internal error)"), nil, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage_findings: %d findings returned (flat page)", len(res.Flat.Findings))}},
		}, res.Flat, nil
	})
}

func triageErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}
