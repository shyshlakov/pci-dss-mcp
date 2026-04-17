package reportscanner_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
)

func newReportSessionForLayerA(t *testing.T) *mcp.ClientSession {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "report-layera", Version: "v0.0.1"}, nil)
	reportscanner.RegisterTools(server, db)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(context.Background(), serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "layera-test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestReportLayerA_SizeBudget(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	absFixture, err := filepath.Abs(fixtureRoot)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	session := newReportSessionForLayerA(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "generate_compliance_report",
		Arguments: map[string]any{
			"path":          absFixture,
			"dep_scan_mode": "offline",
			"min_severity":  "MEDIUM",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("generate_compliance_report Layer A returned IsError: %+v", result)
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := m["response_shape"]; got != "flat" {
		t.Fatalf("response_shape=%v, want flat (min_severity=MEDIUM Layer A)", got)
	}
	const budget = 20480
	t.Logf("report Layer A wire size on golden fixture (min_severity=MEDIUM) = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("report Layer A wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}
