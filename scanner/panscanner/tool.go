package panscanner

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// ScanPANInput is the input type for the scan_pan_data tool.
type ScanPANInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the Go project directory to scan for PAN/CVV data exposure"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Supports directory patterns (vendor/) and file globs (*.pb.go). Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
	IncludeTaint     bool     `json:"include_taint,omitempty" jsonschema:"Enable flow-based severity adjustment using go/packages type analysis . When true, PAN-KEYWORD/PAN-TYPE findings on transit-only struct fields (request/response DTOs, API client models) are downgraded or suppressed per . Adds 5-30 seconds. Default false (opt-in for accuracy vs speed per)"`
}

// defaultExcludes are the default exclusion patterns applied when no custom
// patterns are provided.
var defaultExcludes = []string{"vendor/", "generated/", "*.pb.go", "testdata/", "mocks/"}

// RegisterTools registers the scan_pan_data MCP tool on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name:        "scan_pan_data",
		Description: "Scan Go source and .env files for PAN/CVV data exposure. Detects sensitive variable names, struct fields, function parameters, hardcoded card numbers (Luhn+IIN), string-typed sensitive fields, missing zeroing of []byte data, and logger calls with sensitive arguments. Maps findings to PCI DSS 3.3.1, 3.4.1, 3.5.1.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ScanPANInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
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
		summary := fmt.Sprintf("scan_pan_data: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
