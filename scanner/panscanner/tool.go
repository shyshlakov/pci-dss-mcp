package panscanner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

const scanPANPageSize = 60
const toolNameScanPAN = "scan_pan_data"

type ScanPANInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the Go project directory to scan for PAN/CVV data exposure"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Supports directory patterns (vendor/) and file globs (*.pb.go). Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
	IncludeTaint     bool     `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment using go/packages type analysis . When true, PAN-KEYWORD/PAN-TYPE findings on transit-only struct fields (request/response DTOs, API client models) are downgraded or suppressed per . Adds 5-30 seconds. Default false (opt-in for accuracy vs speed per)"`
	Cursor           string   `json:"cursor,omitempty" jsonschema:"Opaque cursor token from a prior scan_pan_data response. When set, resumes pagination from the stored session cache (10-minute TTL). Leave empty for a fresh scan."`
}

var defaultExcludes = []string{"vendor/", "generated/", "*.pb.go", "testdata/", "mocks/"}

func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_pan_data",
		Description: "Scan Go source and .env files for PAN/CVV data exposure. Detects sensitive variable names, struct fields, function parameters, hardcoded card numbers (Luhn+IIN), string-typed sensitive fields, missing zeroing of []byte data, and logger calls with sensitive arguments. Maps findings to PCI DSS 3.3.1, 3.4.1, 3.5.1. Supports cursor pagination (10-minute TTL) for large projects.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ScanPANInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		if input.Cursor != "" {
			if len(input.ExcludePatterns) > 0 || input.IncludeTests || input.IncludeUntracked || input.IncludeTaint {
				return panErrorResult("scan_pan_data cursor_malformed: cursor + filter/scope params is not supported; re-run without cursor to apply new filters"), nil, nil
			}
			payload, err := hybridcache.DecodeCursor(input.Cursor)
			if err != nil {
				return panErrorResult("scan_pan_data cursor_malformed: " + err.Error()), nil, nil
			}
			if payload.Tool != "" && payload.Tool != toolNameScanPAN {
				return panErrorResult("scan_pan_data cursor_malformed: tool mismatch"), nil, nil
			}
			entry, ok := hybridcache.Get(payload.SID)
			if !ok {
				return panErrorResult("scan_pan_data cursor_expired"), nil, nil
			}
			cached := entry.Findings
			off := payload.Off
			if off < 0 {
				off = 0
			}
			end := off + scanPANPageSize
			if end > len(cached) {
				end = len(cached)
			}
			var page []scanner.Finding
			if off < len(cached) {
				page = cached[off:end]
			}
			out := &scanner.ScannerToolOutput{
				Scanner:       s.Name(),
				Findings:      append([]scanner.Finding{}, page...),
				SeverityStats: countSeverity(page),
				Metadata: scanner.ScanMetadata{
					ScannedFiles: entry.Meta.TotalFiles,
					ScannedLines: entry.Meta.TotalLines,
					DurationMS:   entry.Meta.DurationMS,
				},
				TotalFindings: len(cached),
			}
			if end < len(cached) {
				next, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: payload.SID, Off: end, Tool: toolNameScanPAN})
				if err != nil {
					slog.Warn("scan_pan_data encodeCursor failed", "err", err, "sid", payload.SID, "off", end)
				} else {
					out.NextCursor = next
				}
			}
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("scan_pan_data: resumed page (%d findings, off=%d/%d)", len(page), off, len(cached))}},
			}, out, nil
		}

		excludes := defaultExcludes
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		var result *scanner.ScanResult
		var err error
		if input.IncludeTaint {
			result, err = s.ScanFullWithTaint(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked, true)
		} else {
			result, err = s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
		}
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("scan_pan_data error: %s", err.Error())},
				},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)

		if len(out.Findings) > scanPANPageSize {
			absPath, aerr := filepath.Abs(filepath.Clean(input.Path))
			if aerr != nil {
				absPath = input.Path
			}
			scanTS := time.Now().UTC().Format(time.RFC3339)
			fh := hybridcache.FilterHash("", strings.Join(excludes, ","), input.IncludeTests)
			sid := hybridcache.SessionKey(absPath+"|scan_pan", scanTS, fh, input.IncludeTaint)
			meta := hybridcache.ScanMeta{
				TotalFiles: out.Metadata.ScannedFiles,
				TotalLines: out.Metadata.ScannedLines,
				DurationMS: out.Metadata.DurationMS,
			}
			cached := make([]scanner.Finding, len(out.Findings))
			copy(cached, out.Findings)
			hybridcache.Put(sid, &hybridcache.Entry{Findings: cached, Meta: meta})

			total := len(out.Findings)
			out.TotalFindings = total
			next, err := hybridcache.EncodeCursor(hybridcache.CursorPayload{SID: sid, Off: scanPANPageSize, Tool: toolNameScanPAN})
			if err != nil {
				slog.Warn("scan_pan_data encodeCursor failed", "err", err, "sid", sid, "off", scanPANPageSize)
			} else {
				out.NextCursor = next
			}
			out.Findings = append([]scanner.Finding{}, out.Findings[:scanPANPageSize]...)
			out.SeverityStats = countSeverity(out.Findings)
		}

		summary := fmt.Sprintf("scan_pan_data: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		if out.NextCursor != "" {
			summary += fmt.Sprintf(" (total %d, next_cursor available)", out.TotalFindings)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}

func panErrorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
		IsError: true,
	}
}

func countSeverity(findings []scanner.Finding) scanner.SeverityStats {
	counts := scanner.CountBySeverity(findings)
	return scanner.SeverityStats{
		Critical: counts[scanner.SeverityCritical],
		High:     counts[scanner.SeverityHigh],
		Medium:   counts[scanner.SeverityMedium],
		Low:      counts[scanner.SeverityLow],
		Info:     counts[scanner.SeverityInfo],
	}
}
