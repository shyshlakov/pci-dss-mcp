package depscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybrid"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const toolNameDep = "check_dependencies"

type CheckDepsInput struct {
	Path        string `json:"path" jsonschema:"required,Path to the project directory containing go.mod to scan for vulnerable dependencies"`
	Mode        string `json:"mode,omitempty" jsonschema:"Scan mode: auto (default - try online then offline), online (OSV API only), offline (local cache only)"`
	Cursor      string `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior check_dependencies response. When set resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Maximum number of findings to return after filtering. Default 0 (summary-first). Positive integer for an exact cap. -1 is NO LONGER ACCEPTED (returns error) as of v0.4.0; use cursor pagination instead."`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"Filter by minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO). Setting this forces the flat response shape."`
	RuleFilter  string `json:"rule_filter,omitempty" jsonschema:"Filter by rule ID, comma list or /regex/. Setting this forces the flat response shape."`
}

type UpdateDBInput struct {
	OutputPath string `json:"output_path,omitempty" jsonschema:"Optional path to save the vulnerability cache. Default: ~/.pci-dss-mcp/vuln-cache/go-osv-{date}.json"`
}

type UpdateDBOutput struct {
	CachePath         string `json:"cache_path" jsonschema:"Absolute path to the refreshed OSV cache file"`
	VulnCount         int    `json:"vuln_count" jsonschema:"Number of vulnerabilities indexed in the new cache"`
	DownloadSizeBytes int64  `json:"download_size_bytes" jsonschema:"Raw download size in bytes"`
	PreviousCacheDate string `json:"previous_cache_date,omitempty" jsonschema:"Date of the previous cache (YYYY-MM-DD), empty when no prior cache existed"`
	CustomPath        bool   `json:"custom_path,omitempty" jsonschema:"True when the caller supplied a non-default output_path"`
}

type depCacher struct{}

func (depCacher) Put(sid string, findings []scanner.Finding, meta hybridcache.ScanMeta) {
	cp := make([]scanner.Finding, len(findings))
	copy(cp, findings)
	hybridcache.Put(sid, &hybridcache.Entry{Findings: cp, Meta: meta})
}

func (depCacher) Get(sid string) ([]scanner.Finding, hybridcache.ScanMeta, bool) {
	e, ok := hybridcache.Get(sid)
	if !ok {
		return nil, hybridcache.ScanMeta{}, false
	}
	return e.Findings, e.Meta, true
}

func RegisterTools(server *mcp.Server) {
	s := New()
	schema, err := buildDepOutputSchemaUnion()
	if err != nil {
		slog.Warn("buildDepOutputSchemaUnion failed", "err", err)
	}

	depTool := &mcp.Tool{
		Name: toolNameDep,
		Description: "Scan go.mod dependencies for known vulnerabilities via OSV.dev database (PCI DSS 6.3.3). Modes: 'auto' (default, try online then offline cache), 'online' (OSV API only, fails without network), 'offline' (local cache only). This tool NEVER makes network requests in offline mode. Run update_vulnerability_db first to populate the offline cache. " +
			"Default: returns response_shape \"summary\" with by_severity counts, a capped by_rule histogram (top 10 + more_rules), and top 1 per severity findings - plus a pagination.next_cursor for drill-down. " +
			"Follow the cursor for the full paginated list. " +
			"Use min_severity / rule_filter / positive limit for a filtered flat response. " +
			"Maps findings to PCI DSS 6.3.3.",
		Meta:         mcp.Meta{"anthropic/maxResultSizeChars": 20000},
		OutputSchema: json.RawMessage(schema),
	}

	mcp.AddTool(server, depTool, func(ctx context.Context, req *mcp.CallToolRequest, input CheckDepsInput) (*mcp.CallToolResult, any, error) {
		mode := input.Mode
		if mode == "" {
			mode = "auto"
		}
		if mode != "auto" && mode != "online" && mode != "offline" {
			return depErrorResult(fmt.Sprintf("Invalid mode %q. Valid modes: auto, online, offline", mode)), nil, nil
		}

		if input.Limit == -1 {
			return depErrorResult("LIMIT_MINUS_ONE_REMOVED: limit=-1 is no longer accepted. For interactive use, call with default params (summary-first with next_cursor) or apply min_severity/rule_filter for a paged flat response; follow the cursor for subsequent pages."), nil, nil
		}

		qualityFilterSet := strings.TrimSpace(input.MinSeverity) != "" || strings.TrimSpace(input.RuleFilter) != ""
		if input.Cursor != "" && (qualityFilterSet || input.Limit > 0) {
			return depErrorResult("check_dependencies cursor_malformed: cursor + filter/limit params is not supported; re-run without cursor to apply new filters"), nil, nil
		}

		absPath, aerr := filepath.Abs(filepath.Clean(input.Path))
		if aerr != nil {
			absPath = input.Path
		}
		scanTS := time.Now().UTC().Format(time.RFC3339)

		scan := func(ctx context.Context, _ hybrid.Input) ([]scanner.Finding, hybridcache.ScanMeta, error) {
			result, serr := s.ScanWithMode(ctx, input.Path, mode)
			if serr != nil {
				return nil, hybridcache.ScanMeta{}, serr
			}
			out := scanner.BuildScannerToolOutput(s.Name(), result)
			return append([]scanner.Finding{}, out.Findings...), hybridcache.ScanMeta{
				TotalFiles: out.Metadata.ScannedFiles,
				TotalLines: out.Metadata.ScannedLines,
				DurationMS: out.Metadata.DurationMS,
			}, nil
		}

		filterFunc := func(findings []scanner.Finding, minSev, ruleFilter string) ([]scanner.Finding, error) {
			if minSev == "" && ruleFilter == "" {
				return findings, nil
			}
			out := make([]scanner.Finding, 0, len(findings))
			for _, f := range findings {
				if minSev != "" && !severityMeets(f.Severity, minSev) {
					continue
				}
				if ruleFilter != "" && !ruleMatches(f.RuleID, ruleFilter) {
					continue
				}
				out = append(out, f)
			}
			return out, nil
		}

		buildSummary := func(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *DepSummaryResponse {
			return buildDepSummaryInternal(findings, meta, sid, nextCursor)
		}

		buildFlat := func(findings []scanner.Finding, off, pageSize, total int, meta hybridcache.ScanMeta, sid, nextCursor string, autoCapped bool) *scanner.ScannerToolOutput {
			counts := scanner.CountBySeverity(findings)
			out := &scanner.ScannerToolOutput{
				ResponseShape: "flat",
				Scanner:       s.Name(),
				Findings:      append([]scanner.Finding{}, findings...),
				SeverityStats: scanner.SeverityStats{
					Critical: counts[scanner.SeverityCritical],
					High:     counts[scanner.SeverityHigh],
					Medium:   counts[scanner.SeverityMedium],
					Low:      counts[scanner.SeverityLow],
					Info:     counts[scanner.SeverityInfo],
				},
				Metadata: scanner.ScanMetadata{
					ScannedFiles: meta.TotalFiles,
					ScannedLines: meta.TotalLines,
					DurationMS:   meta.DurationMS,
				},
				TotalFindings: total,
				NextCursor:    nextCursor,
			}
			return out
		}

		effectiveLimit := input.Limit
		effectiveMinSev := strings.TrimSpace(input.MinSeverity)
		effectiveRule := strings.TrimSpace(input.RuleFilter)

		in := hybrid.Input{
			AbsPath:       absPath,
			Cursor:        input.Cursor,
			MinSeverity:   effectiveMinSev,
			RuleFilter:    effectiveRule,
			Limit:         effectiveLimit,
			ScanTimestamp: scanTS,
			ToolName:      toolNameDep,
			FlatPageSize:  15,
		}

		res, sErr := hybrid.SelectAndExecute[scanner.Finding, DepSummaryResponse, scanner.ScannerToolOutput](
			ctx, in, scan, filterFunc, buildSummary, buildFlat, depCacher{},
		)
		if sErr != nil {
			return depErrorResult(fmt.Sprintf(
				"check_dependencies error: %s\n\n"+
					"action_required: Run update_vulnerability_db to download OSV cache\n"+
					"pci_impact: PCI DSS 6.3.3 compliance cannot be verified without vulnerability data",
				sErr.Error())), nil, nil
		}
		if res.Err != nil {
			cerr := &DepCursorError{
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
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("check_dependencies: %d findings (summary with top %d per severity)", res.Summary.Pagination.TotalFindings, TopNPerSeverityDep)}},
			}, res.Summary, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("check_dependencies: %d findings returned (flat page)", len(res.Flat.Findings))}},
		}, res.Flat, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: "update_vulnerability_db",
		Description: "Download fresh OSV Go vulnerability snapshot to local cache for offline scanning. " +
			"Downloads from gs://osv-vulnerabilities/Go/all.zip (~7.5MB). " +
			"This is the ONLY tool that makes network requests. " +
			"Cache stored at PCI_MCP_CACHE_DIR or ~/.pci-dss-mcp/vuln-cache/ by default.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateDBInput) (*mcp.CallToolResult, *UpdateDBOutput, error) {
		outputDir := resolveCachePath()
		if input.OutputPath != "" {
			outputDir = input.OutputPath
		}
		outputPath := filepath.Join(outputDir,
			fmt.Sprintf("go-osv-%s.json", time.Now().Format("2006-01-02")))

		result, err := downloadAndBuildCache(ctx, outputPath, osvGoZipURL)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"update_vulnerability_db error: %s", err.Error())}},
				IsError: true,
			}, nil, nil
		}

		out := &UpdateDBOutput{
			CachePath:         result.CachePath,
			VulnCount:         result.VulnCount,
			DownloadSizeBytes: result.DownloadSize,
			CustomPath:        input.OutputPath != "",
		}
		if result.PreviousCacheDate != nil {
			out.PreviousCacheDate = result.PreviousCacheDate.Format("2006-01-02")
		}

		summary := fmt.Sprintf("update_vulnerability_db: %d vulnerabilities cached at %s (%.1f MB)",
			out.VulnCount, out.CachePath, float64(out.DownloadSizeBytes)/(1024*1024))

		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}

func severityMeets(sev scanner.Severity, minSev string) bool {
	min, ok := parseSeverity(minSev)
	if !ok {
		return true
	}
	return sev <= min
}

func parseSeverity(s string) (scanner.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return scanner.SeverityCritical, true
	case "HIGH":
		return scanner.SeverityHigh, true
	case "MEDIUM":
		return scanner.SeverityMedium, true
	case "LOW":
		return scanner.SeverityLow, true
	case "INFO":
		return scanner.SeverityInfo, true
	}
	return scanner.SeverityInfo, false
}

func ruleMatches(ruleID, filter string) bool {
	f := strings.TrimSpace(filter)
	if f == "" {
		return true
	}
	if strings.HasPrefix(f, "/") && strings.HasSuffix(f, "/") && len(f) >= 2 {
		pat := strings.Trim(f, "/")
		re, err := regexp.Compile(pat)
		if err != nil {
			slog.Warn("ruleMatches: invalid regex in rule_filter", "pattern", pat, "err", err)
			return false
		}
		return re.MatchString(ruleID)
	}
	for _, id := range strings.Split(f, ",") {
		if strings.TrimSpace(id) == ruleID {
			return true
		}
	}
	return false
}

func depErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}
