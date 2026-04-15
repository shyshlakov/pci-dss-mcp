package scanner_test

import (
	"context"
	"testing"

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

// TestAllMCPToolsHaveOutputSchema is the acceptance gate: every MCP
// tool registered in main.go must declare a non-nil OutputSchema. The MCP
// SDK auto-infers OutputSchema from the typed AddTool[In, Out] generic when
// Out is not 'any' — so a missing schema here means someone regressed back
// to `any` output. The test spins up an in-memory transport pair, registers
// every tool in the same order as main.go, and walks the tool list via
// tools/list to assert the schema is present.
func TestAllMCPToolsHaveOutputSchema(t *testing.T) {
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-schema-test", Version: "test"}, nil)

	// Mirror main.go registration order.
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

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	go func() {
		if err := server.Run(context.Background(), serverTransport); err != nil {
			return
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "pci-dss-mcp-schema-client", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer session.Close()

	resp, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(resp.Tools) < 13 {
		t.Fatalf("expected at least 13 tools registered, got %d", len(resp.Tools))
	}

	var missing []string
	for _, tool := range resp.Tools {
		if tool.OutputSchema == nil {
			missing = append(missing, tool.Name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf(" violation: tools without OutputSchema: %v", missing)
	}

	t.Logf("verified %d tools have non-nil OutputSchema", len(resp.Tools))
}
