package triagescanner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
)

const triagePageSize = 60
const toolNameTriage = "triage_findings"

type TriageInput struct {
	Path         string `json:"path" jsonschema:"Path to the Go project to triage. If empty, uses current directory (.)"`
	DepScanMode  string `json:"dep_scan_mode,omitempty" jsonschema:"Dependency scanner mode: auto (default), online, offline"`
	IncludeTests bool   `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false"`
	IncludeTaint *bool  `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment via go/packages type analysis. When true, panscanner downgrades PAN-KEYWORD and suppresses PAN-TYPE findings for transit-only CHD fields. Adds 5-30 seconds to scan time. Default true (production-grade precision, matches generate_compliance_report). Set false for fast dev iteration. Requires 'go' binary on PATH; falls back to AST-only scanning on failure."`
	MinSeverity  string `json:"min_severity,omitempty" jsonschema:"Filter findings by minimum severity. One of CRITICAL / HIGH / MEDIUM / LOW / INFO (case-insensitive). Default: no severity filter. Applied BEFORE enrichment to save context-collection cost."`
	RuleFilter   string `json:"rule_filter,omitempty" jsonschema:"Filter findings by rule ID. Comma-separated list for exact match (e.g. PAN-KEYWORD,PAN-TYPE) OR a single regex in leading/trailing slashes (e.g. /PAN-.*/). Default: no rule filter."`
	Limit        int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to enrich after filtering. Default 0 (unlimited). Use to cap triage cost on noisy projects."`
	Cursor       string `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior triage_findings response. When set, resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
}

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
			"for fast dev iteration. Supports cursor pagination (10-minute TTL) via the " +
			"cursor input; server caches the unfiltered finding slice and pages 60 at a " +
			"time through it on resume.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input TriageInput) (*mcp.CallToolResult, *TriageResult, error) {
		path := strings.TrimSpace(input.Path)
		if path == "" {
			path = "."
		}

		if input.DepScanMode != "" && input.DepScanMode != "auto" && input.DepScanMode != "online" && input.DepScanMode != "offline" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"Invalid dep_scan_mode %q. Valid modes: auto, online, offline", input.DepScanMode)}},
				IsError: true,
			}, nil, nil
		}

		includeTaint := true
		if input.IncludeTaint != nil {
			includeTaint = *input.IncludeTaint
		}

		if input.Cursor != "" {
			if input.MinSeverity != "" || input.RuleFilter != "" || input.Limit > 0 || input.IncludeTests || input.DepScanMode != "" || input.IncludeTaint != nil {
				return triageErrorResult("triage_findings cursor_malformed: cursor + filter/scope params is not supported; re-run without cursor to apply new filters"), nil, nil
			}
			payload, err := hybridcache.DecodeCursor(input.Cursor)
			if err != nil {
				return triageErrorResult("triage_findings cursor_malformed: " + err.Error()), nil, nil
			}
			if payload.Tool != "" && payload.Tool != toolNameTriage {
				return triageErrorResult("triage_findings cursor_malformed: tool mismatch"), nil, nil
			}
			entry, ok := hybridcache.Get(payload.SID)
			if !ok {
				return triageErrorResult("triage_findings cursor_expired"), nil, nil
			}
			cached := entry.Findings
			off := payload.Off
			if off < 0 {
				off = 0
			}
			if off >= len(cached) {
				empty := &TriageResult{Findings: []EnrichedFinding{}, Metadata: TriageMetadata{FindingsTotal: len(cached)}}
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "triage_findings: end of cursor stream"}},
				}, empty, nil
			}
			end := off + triagePageSize
			if end > len(cached) {
				end = len(cached)
			}
			page := cached[off:end]
			result, terr := engine.Triage(ctx, path, page)
			if terr != nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage error: %s", terr.Error())}},
					IsError: true,
				}, nil, nil
			}
			if end < len(cached) {
				next, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: payload.SID, Off: end, Tool: toolNameTriage})
				if err != nil {
					slog.Warn("triage_findings encodeCursor failed", "err", err, "sid", payload.SID, "off", end)
				} else {
					result.NextCursor = next
				}
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage_findings: resumed page (%d findings, off=%d/%d)", len(page), off, len(cached))}},
			}, result, nil
		}

		gen := reportscanner.NewReportGenerator(db)
		report, err := gen.GenerateWithOptions(ctx, path, input.DepScanMode, input.IncludeTests, includeTaint)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage_findings error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		findings := make([]scanner.Finding, 0, len(report.Findings))
		for _, rf := range report.Findings {
			findings = append(findings, rf.Finding)
		}

		if input.MinSeverity != "" || input.RuleFilter != "" || input.Limit > 0 {
			filtered, ferr := reportscanner.FilterFindings(findings, input.MinSeverity, input.RuleFilter, input.Limit)
			if ferr != nil {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("rule_filter error: %s", ferr.Error())}},
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

		absPath, err := filepath.Abs(filepath.Clean(path))
		if err != nil {
			absPath = path
		}
		scanTS := time.Now().UTC().Format(time.RFC3339)
		fh := hybridcache.FilterHash(input.MinSeverity, input.RuleFilter, input.IncludeTests)
		sid := hybridcache.SessionKey(absPath+"|triage", scanTS, fh, includeTaint)
		meta := hybridcache.ScanMeta{
			TotalFiles: report.Metadata.TotalFiles,
			TotalLines: report.Metadata.TotalLines,
			DurationMS: report.Metadata.DurationMS,
		}
		cached := make([]scanner.Finding, len(findings))
		copy(cached, findings)
		hybridcache.Put(sid, &hybridcache.Entry{Findings: cached, Meta: meta})

		pageEnd := len(findings)
		if pageEnd > triagePageSize {
			pageEnd = triagePageSize
		}
		firstPage := findings[:pageEnd]

		result, terr := engine.Triage(ctx, path, firstPage)
		if terr != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("triage error: %s", terr.Error())}},
				IsError: true,
			}, nil, nil
		}
		// Preserve the parity contract at the MCP layer: FindingsTotal reflects
		// the pre-pagination input count so generate_compliance_report and
		// triage_findings agree on scope after the taint default sync. The
		// enriched slice shrinks with each page, but the headline total does
		// not.
		result.Metadata.FindingsTotal = len(findings)
		if pageEnd < len(findings) {
			next, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: sid, Off: pageEnd, Tool: toolNameTriage})
			if err != nil {
				slog.Warn("triage_findings encodeCursor failed", "err", err, "sid", sid, "off", pageEnd)
			} else {
				result.NextCursor = next
			}
		}

		summary := fmt.Sprintf(
			"%d findings triaged in %dms (%d files analyzed). Structured results in tool output.",
			result.Metadata.FindingsTriaged,
			result.Metadata.DurationMS,
			result.Metadata.FilesAnalyzed,
		)
		if result.NextCursor != "" {
			summary += " More findings available via next_cursor."
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, result, nil
	})
}

func triageErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}
