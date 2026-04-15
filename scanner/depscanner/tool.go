package depscanner

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// CheckDepsInput is the input type for the check_dependencies MCP tool.
type CheckDepsInput struct {
	Path string `json:"path" jsonschema:"required,Path to the project directory containing go.mod to scan for vulnerable dependencies"`
	Mode string `json:"mode,omitempty" jsonschema:"Scan mode: auto (default - try online then offline), online (OSV API only), offline (local cache only)"`
}

// UpdateDBInput is the input type for the update_vulnerability_db MCP tool.
type UpdateDBInput struct {
	OutputPath string `json:"output_path,omitempty" jsonschema:"Optional path to save the vulnerability cache. Default: ~/.pci-dss-mcp/vuln-cache/go-osv-{date}.json"`
}

// UpdateDBOutput is the typed MCP output for update_vulnerability_db. The
// SDK auto-infers OutputSchema from the jsonschema struct tags.
type UpdateDBOutput struct {
	CachePath         string `json:"cache_path" jsonschema:"Absolute path to the refreshed OSV cache file"`
	VulnCount         int    `json:"vuln_count" jsonschema:"Number of vulnerabilities indexed in the new cache"`
	DownloadSizeBytes int64  `json:"download_size_bytes" jsonschema:"Raw download size in bytes"`
	PreviousCacheDate string `json:"previous_cache_date,omitempty" jsonschema:"Date of the previous cache (YYYY-MM-DD), empty when no prior cache existed"`
	CustomPath        bool   `json:"custom_path,omitempty" jsonschema:"True when the caller supplied a non-default output_path"`
}

// RegisterTools registers the check_dependencies and update_vulnerability_db
// MCP tools on the given server.
func RegisterTools(server *mcp.Server) {
	s := New()

	// Tool 1: check_dependencies
	mcp.AddTool(server, &mcp.Tool{
		Name: "check_dependencies",
		Description: "Scan go.mod dependencies for known vulnerabilities via OSV.dev database " +
			"(PCI DSS 6.3.3). Modes: 'auto' (default, try online then offline cache), " +
			"'online' (OSV API only, fails without network), 'offline' (local cache only). " +
			"This tool NEVER makes network requests in offline mode. " +
			"Run update_vulnerability_db first to populate the offline cache.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CheckDepsInput) (*mcp.CallToolResult, *scanner.ScannerToolOutput, error) {
		mode := input.Mode
		if mode == "" {
			mode = "auto" //  default
		}
		// Validate mode parameter per T-08-10.
		if mode != "auto" && mode != "online" && mode != "offline" {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"Invalid mode %q. Valid modes: auto, online, offline", mode)}},
				IsError: true,
			}, nil, nil
		}

		result, err := s.ScanWithMode(ctx, input.Path, mode)
		if err != nil {
			// no cache + no network returns structured error with action guidance.
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(
					"check_dependencies error: %s\n\n"+
						"action_required: Run update_vulnerability_db to download OSV cache\n"+
						"pci_impact: PCI DSS 6.3.3 compliance cannot be verified without vulnerability data",
					err.Error())}},
				IsError: true,
			}, nil, nil
		}

		out := scanner.BuildScannerToolOutput(s.Name(), result)
		summary := fmt.Sprintf("check_dependencies: %d findings (%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO) in %dms",
			len(out.Findings),
			out.SeverityStats.Critical, out.SeverityStats.High, out.SeverityStats.Medium,
			out.SeverityStats.Low, out.SeverityStats.Info,
			out.Metadata.DurationMS)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})

	// Tool 2: update_vulnerability_db
	mcp.AddTool(server, &mcp.Tool{
		Name: "update_vulnerability_db",
		Description: "Download fresh OSV Go vulnerability snapshot to local cache for offline scanning. " +
			"Downloads from gs://osv-vulnerabilities/Go/all.zip (~7.5MB). " +
			"This is the ONLY tool that makes network requests. " +
			"Cache stored at PCI_MCP_CACHE_DIR or ~/.pci-dss-mcp/vuln-cache/ by default.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input UpdateDBInput) (*mcp.CallToolResult, *UpdateDBOutput, error) {
		outputDir := resolveCachePath()
		// optional output_path override.
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
