package errorscanner

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CheckErrorHandlingInput is the input type for the check_error_handling tool.
type CheckErrorHandlingInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the Go project directory to scan for error handling violations in payment handlers"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Supports directory patterns (vendor/) and file globs (*.pb.go). Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
}

// defaultExcludes are the default exclusion patterns applied when no custom
// patterns are provided.
var defaultExcludes = []string{"vendor/", "generated/", "*.pb.go", "testdata/", "mocks/"}

// RegisterTools registers the check_error_handling MCP tool on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_error_handling",
		Description: "Scan Go source files for payment handler error disclosure: detects err.Error() in http.Error, fmt.Fprintf with error variables, w.Write with error bytes, and json.Encode of errors. Maps findings to PCI DSS 6.2.4.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CheckErrorHandlingInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		excludes := defaultExcludes
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		result, err := s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("check_error_handling error: %s", err.Error())},
				},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)
		summary := fmt.Sprintf("check_error_handling: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
