package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/auditscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/authscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/depscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/errorscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/retentionscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/sbomscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/tlsscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

const serverInstructions = `pci-dss-mcp scans Go payment service codebases for PCI DSS v4.0.1 violations.

Entry point selection:
- For "scan this project" or any open-ended audit request, call triage_findings. It runs all PCI DSS v4.0.1 scanners plus AI classification and file:line context in one call.
- For CI gates, audit artifacts, or raw requirement pass/fail lists, call generate_compliance_report. Do NOT call it in addition to triage_findings — triage already runs the same scanner pipeline.
- For targeted questions ("only check PAN handling", "just audit my TLS config"), call the specific single-purpose scanner (scan_pan_data, check_tls_config, check_encryption, etc.).

Path argument must be an absolute path to a directory containing go.mod. When the server runs inside a container, the filesystem is limited to whatever the user bind-mounted. If a scan returns 0 findings AND 0 checked files AND no error, the path is outside the container mount — ask the user to widen the mount (or rerun from a project under the existing mount) before retrying.

Performance: the first call per project root pays a 5–30 s taint engine load; subsequent calls on the same root are session-cached.

On large codebases, prefer min_severity=MEDIUM and follow pagination.next_cursor. Every finding carries a PCI DSS requirement_id; use explain_requirement to look up what a requirement means.`

func main() {
	// CRITICAL: Preserve the real stdout for MCP JSON-RPC transport,
	// then redirect os.Stdout to stderr so stray fmt.Print/log calls
	// don't corrupt the MCP stream.
	mcpStdout := os.Stdout
	os.Stdout = os.Stderr

	// All logging goes to stderr.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Load embedded PCI DSS database.
	db, err := pcidb.New()
	if err != nil {
		slog.Error("failed to load PCI DSS database", "error", err)
		os.Exit(1)
	}
	slog.Info("PCI DSS database loaded", "requirements", db.Count())

	// Create MCP server.
	server := mcp.NewServer(
		&mcp.Implementation{Name: "pci-dss-mcp", Version: "v0.6.2"},
		&mcp.ServerOptions{Instructions: serverInstructions},
	)

	// Register tools.
	pcidb.RegisterTools(server, db)
	auditscanner.RegisterTools(server)
	authscanner.RegisterTools(server)
	cryptoscanner.RegisterTools(server)
	depscanner.RegisterTools(server)
	errorscanner.RegisterTools(server)
	panscanner.RegisterTools(server)
	retentionscanner.RegisterTools(server)
	sbomscanner.RegisterTools(server)
	scriptscanner.RegisterTools(server)
	secretscanner.RegisterTools(server)
	tlsscanner.RegisterTools(server)
	reportscanner.RegisterTools(server, db)
	triagescanner.RegisterTools(server, db)

	// Run on stdio transport using the preserved stdout (blocks until client disconnects).
	// Cannot use StdioTransport{} because os.Stdout was redirected to stderr above.
	slog.Info("starting MCP server on stdio")
	if err := server.Run(context.Background(), &mcp.IOTransport{Reader: os.Stdin, Writer: mcpStdout}); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
