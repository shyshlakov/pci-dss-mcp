package scriptscanner

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CheckPaymentPageScriptsInput is the input type for the check_payment_page_scripts tool.
type CheckPaymentPageScriptsInput struct {
	Path             string   `json:"path" jsonschema:"required,Path to the project directory to scan for payment page script security violations (CSP headers in Go handlers and SRI/nonce in HTML templates)"`
	ExcludePatterns  []string `json:"exclude_patterns,omitempty" jsonschema:"Optional glob patterns to exclude. Default: vendor/ generated/ *.pb.go testdata/ mocks/"`
	IncludeTests     bool     `json:"include_tests,omitempty" jsonschema:"Include _test.go files in scan results. Default false excludes test files per industry SAST consensus "`
	IncludeUntracked bool     `json:"include_untracked,omitempty" jsonschema:"Scan all files including .gitignored. Default false scans only git-tracked files "`
}

// RegisterTools registers the check_payment_page_scripts MCP tool on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	mcp.AddTool(server, &mcp.Tool{
		Name: "check_payment_page_scripts",
		Description: "Scan Go source files and HTML templates for payment page script security " +
			"violations (PCI DSS 6.4.3, 11.6.1). Detects: missing Content-Security-Policy headers " +
			"in Go payment handlers, unsafe-inline/unsafe-eval in CSP, external scripts without SRI " +
			"(integrity attribute) in HTML templates, inline scripts without nonce attribute. " +
			"Framework-aware: supports net/http, gin, echo handler signatures.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CheckPaymentPageScriptsInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		if input.Path == "" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: "check_payment_page_scripts error: path parameter is required"},
				},
				IsError: true,
			}, nil, nil
		}

		excludes := defaultExcludePatterns
		if len(input.ExcludePatterns) > 0 {
			excludes = input.ExcludePatterns
		}

		result, err := s.ScanFull(ctx, input.Path, excludes, input.IncludeTests, input.IncludeUntracked)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: fmt.Sprintf("check_payment_page_scripts error: %s", err.Error())},
				},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)
		summary := fmt.Sprintf("check_payment_page_scripts: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
