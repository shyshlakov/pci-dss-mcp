package tlsscanner

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CheckTLSInput is the input type for the check_tls_config tool.
type CheckTLSInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the Go project directory to scan for TLS configuration violations"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Supports directory patterns (vendor/) and file globs (*.pb.go). Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
}

// defaultExcludes are the default exclusion patterns applied when no custom
// patterns are provided.
var defaultExcludes = []string{"vendor/", "generated/", "*.pb.go", "testdata/", "mocks/"}

// RegisterTools registers the check_tls_config MCP tool on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name:        "check_tls_config",
		Description: "Scan Go source files for TLS configuration violations: InsecureSkipVerify, weak MinVersion (below TLS 1.2), missing MinVersion, and prohibited cipher suites (RC4, 3DES, NULL). Maps findings to PCI DSS 4.2.1.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CheckTLSInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		excludes := defaultExcludes
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		result, err := s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("check_tls_config error: %s", err.Error())},
				},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)
		summary := fmt.Sprintf("check_tls_config: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
