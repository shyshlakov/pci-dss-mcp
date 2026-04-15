package retentionscanner

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CheckDataRetentionInput is the input type for the check_data_retention tool.
type CheckDataRetentionInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to scan for unsafe data retention patterns (Redis/DB without TTL, config missing TTL, memory zeroing timing)"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
}

// RegisterTools registers the check_data_retention MCP tool on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_data_retention",
		Description: "Scan Go source and config files for unsafe data retention: " +
			"Redis/DB storage of CVV/PAN without TTL (PCI DSS 3.2.1), config files missing TTL " +
			"on sensitive keys (PCI DSS 3.3.1), and incorrect memory zeroing timing after " +
			"authorization. Scans .go, .yaml, .json, .toml files.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CheckDataRetentionInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		excludes := defaultExcludePatterns
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		result, err := s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("check_data_retention error: %s", err.Error())},
				},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)
		summary := fmt.Sprintf("check_data_retention: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
