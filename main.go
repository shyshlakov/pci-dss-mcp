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
	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/tlsscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

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
		&mcp.Implementation{Name: "pci-dss-mcp", Version: "v0.1.0"},
		nil,
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
