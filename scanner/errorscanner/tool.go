package errorscanner

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

const toolNameError = "check_error_handling"

type CheckErrorHandlingInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the Go project directory to scan for error handling violations in payment handlers"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Supports directory patterns (vendor/) and file globs (*.pb.go). Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus"`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files"`
	Cursor           string   `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior check_error_handling response. When set resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
	Limit            int      `json:"limit,omitempty" jsonschema:"Maximum number of findings to return after filtering. Default 0 (summary-first). Positive integer for an exact cap. -1 is NO LONGER ACCEPTED (returns error) as of v0.4.0; use cursor pagination instead."`
	MinSeverity      string   `json:"min_severity,omitempty" jsonschema:"Filter by minimum severity (CRITICAL/HIGH/MEDIUM/LOW/INFO). Setting this forces the flat response shape."`
	RuleFilter       string   `json:"rule_filter,omitempty" jsonschema:"Filter by rule ID, comma list or /regex/. Setting this forces the flat response shape."`
}

var defaultExcludes = []string{"vendor/", "generated/", "*.pb.go", "testdata/", "mocks/"}

type errorCacher struct{}

func (errorCacher) Put(sid string, findings []scanner.Finding, meta hybridcache.ScanMeta) {
	cp := make([]scanner.Finding, len(findings))
	copy(cp, findings)
	hybridcache.Put(sid, &hybridcache.Entry{Findings: cp, Meta: meta})
}

func (errorCacher) Get(sid string) ([]scanner.Finding, hybridcache.ScanMeta, bool) {
	e, ok := hybridcache.Get(sid)
	if !ok {
		return nil, hybridcache.ScanMeta{}, false
	}
	return e.Findings, e.Meta, true
}

func RegisterTools(server *mcp.Server) {
	s := New()
	schema, err := buildErrorOutputSchemaUnion()
	if err != nil {
		slog.Warn("buildErrorOutputSchemaUnion failed", "err", err)
	}

	tool := &mcp.Tool{
		Name: toolNameError,
		Description: "Scan Go source files for payment handler error disclosure: detects err.Error() in http.Error, fmt.Fprintf with error variables, w.Write with error bytes, and json.Encode of errors. " +
			"Default: returns response_shape \"summary\" with by_severity counts, a capped by_rule histogram (top 10 + more_rules), and top 3 per severity findings - plus a pagination.next_cursor for drill-down. " +
			"Follow the cursor for the full paginated list. " +
			"Use include_tests / exclude_patterns / min_severity / rule_filter for a filtered flat response. " +
			"Maps findings to PCI DSS 6.2.4.",
		Meta:         mcp.Meta{"anthropic/maxResultSizeChars": 20000},
		OutputSchema: json.RawMessage(schema),
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, input CheckErrorHandlingInput) (*mcp.CallToolResult, any, error) {
		if input.Limit == -1 {
			return errorErrorResult("LIMIT_MINUS_ONE_REMOVED: limit=-1 is no longer accepted. For interactive use, call with default params (summary-first with next_cursor) or apply min_severity/rule_filter for a paged flat response; follow the cursor for subsequent pages."), nil, nil
		}
		scopeFilterSet := len(input.ExcludePatterns) > 0 || input.IncludeTests || input.IncludeUntracked
		qualityFilterSet := strings.TrimSpace(input.MinSeverity) != "" || strings.TrimSpace(input.RuleFilter) != ""
		if input.Cursor != "" && (scopeFilterSet || qualityFilterSet) {
			return errorErrorResult("check_error_handling cursor_malformed: cursor + filter/scope params is not supported; re-run without cursor to apply new filters"), nil, nil
		}

		excludes := defaultExcludes
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		absPath, aerr := filepath.Abs(filepath.Clean(input.Path))
		if aerr != nil {
			absPath = input.Path
		}
		scanTS := time.Now().UTC().Format(time.RFC3339)

		scan := func(ctx context.Context, _ hybrid.Input) ([]scanner.Finding, hybridcache.ScanMeta, error) {
			result, serr := s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
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

		buildSummary := func(findings []scanner.Finding, meta hybridcache.ScanMeta, sid, nextCursor string) *ErrorSummaryResponse {
			return buildErrorSummaryInternal(findings, meta, sid, nextCursor)
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
		if scopeFilterSet && effectiveLimit == 0 && effectiveMinSev == "" && effectiveRule == "" && input.Cursor == "" {
			effectiveLimit = 30
		}

		in := hybrid.Input{
			AbsPath:       absPath,
			Cursor:        input.Cursor,
			MinSeverity:   effectiveMinSev,
			RuleFilter:    effectiveRule,
			Limit:         effectiveLimit,
			IncludeTests:  input.IncludeTests,
			ScanTimestamp: scanTS,
			ToolName:      toolNameError,
			FlatPageSize:  30,
		}

		res, sErr := hybrid.SelectAndExecute[scanner.Finding, ErrorSummaryResponse, scanner.ScannerToolOutput](
			ctx, in, scan, filterFunc, buildSummary, buildFlat, errorCacher{},
		)
		if sErr != nil {
			return errorErrorResult(fmt.Sprintf("check_error_handling error: %s", sErr.Error())), nil, nil
		}
		if res.Err != nil {
			cerr := &ErrorCursorError{
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
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("check_error_handling: %d findings (summary with top %d per severity)", res.Summary.Pagination.TotalFindings, TopNPerSeverityError)}},
			}, res.Summary, nil
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("check_error_handling: %d findings returned (flat page)", len(res.Flat.Findings))}},
		}, res.Flat, nil
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

func errorErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}
