package scanner_test

import (
	"context"
	"encoding/json"
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

// TestOutputSchema_GenerateReport_HasOneOfUnion verifies that the
// generate_compliance_report MCP tool declares its output schema as a
// oneOf union of SummaryResponse, FlatResponse, and CursorExpiredError —
// the three-layer hybrid response shape mandated by CONTEXT D-04. Without
// this, AI clients cannot tell which variant they received without parsing
// the response_shape discriminator by hand.
func TestOutputSchema_GenerateReport_HasOneOfUnion(t *testing.T) {
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-union-test", Version: "test"}, nil)
	reportscanner.RegisterTools(server, db)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() {
		_ = server.Run(context.Background(), serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "pci-dss-mcp-union-client", Version: "test"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer session.Close()

	resp, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var reportTool *mcp.Tool
	for _, tool := range resp.Tools {
		if tool.Name == "generate_compliance_report" {
			reportTool = tool
			break
		}
	}
	if reportTool == nil {
		t.Fatalf("generate_compliance_report tool not registered")
	}

	raw, err := json.Marshal(reportTool.OutputSchema)
	if err != nil {
		t.Fatalf("marshal OutputSchema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal OutputSchema: %v", err)
	}

	oneOfAny, ok := schema["oneOf"]
	if !ok {
		t.Fatalf("generate_compliance_report OutputSchema missing oneOf, got %s", string(raw))
	}
	oneOf, ok := oneOfAny.([]any)
	if !ok {
		t.Fatalf("oneOf is not an array, got %T", oneOfAny)
	}
	if len(oneOf) != 3 {
		t.Fatalf("oneOf has %d members, want 3 (summary/flat/error)", len(oneOf))
	}

	gotDiscriminators := make(map[string]bool)
	for i, variant := range oneOf {
		vmap, ok := variant.(map[string]any)
		if !ok {
			t.Fatalf("oneOf[%d] is not an object, got %T", i, variant)
		}
		props, ok := vmap["properties"].(map[string]any)
		if !ok {
			continue
		}
		rs, ok := props["response_shape"].(map[string]any)
		if !ok {
			continue
		}
		if c, ok := rs["const"].(string); ok && c != "" {
			gotDiscriminators[c] = true
		}
	}

	for _, want := range []string{"summary", "flat", "error"} {
		if !gotDiscriminators[want] {
			t.Fatalf("oneOf missing response_shape.const = %q, got discriminators %v (raw schema: %s)", want, gotDiscriminators, string(raw))
		}
	}
}
