package hybrid_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

func newCrossToolSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "layerb-crosstool", Version: "v0.0.1"}, nil)
	triagescanner.RegisterTools(server, db)
	panscanner.RegisterTools(server)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() { _ = server.Run(context.Background(), serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "layerb-crosstool-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestLayerB_CrossTool_SizeBudget(t *testing.T) {
	fixture := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	absFixture, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	session := newCrossToolSession(t)
	ctx := context.Background()

	triageRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "triage_findings",
		Arguments: map[string]any{
			"path":          absFixture,
			"dep_scan_mode": "offline",
			"include_taint": true,
		},
	})
	if err != nil {
		t.Fatalf("triage_findings: %v", err)
	}
	if triageRes.IsError {
		t.Fatalf("triage_findings IsError: %+v", triageRes)
	}
	triageBytes, err := json.Marshal(triageRes.StructuredContent)
	if err != nil {
		t.Fatalf("marshal triage: %v", err)
	}

	panRes, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "scan_pan_data",
		Arguments: map[string]any{
			"path": absFixture,
		},
	})
	if err != nil {
		t.Fatalf("scan_pan_data: %v", err)
	}
	if panRes.IsError {
		t.Fatalf("scan_pan_data IsError: %+v", panRes)
	}
	panBytes, err := json.Marshal(panRes.StructuredContent)
	if err != nil {
		t.Fatalf("marshal pan: %v", err)
	}

	const budget = 20480
	const triageTightBudget = 10000
	t.Logf("cross-tool Layer B wire sizes (golden fixture):")
	t.Logf("  triage_findings = %6d bytes (budget %d)  %s", len(triageBytes), budget, budgetVerdict(len(triageBytes), budget))
	t.Logf("  scan_pan_data   = %6d bytes (budget %d)  %s", len(panBytes), budget, budgetVerdict(len(panBytes), budget))
	t.Logf("  triage tight budget = %d (G-01 safety margin with N=1)", triageTightBudget)

	if len(triageBytes) >= budget {
		t.Errorf("triage_findings Layer B %d bytes exceeds budget %d", len(triageBytes), budget)
	}
	if len(panBytes) >= budget {
		t.Errorf("scan_pan_data Layer B %d bytes exceeds budget %d", len(panBytes), budget)
	}
	if len(triageBytes) >= triageTightBudget {
		t.Errorf("triage_findings Layer B %d bytes exceeds tight budget %d (G-01 regression)", len(triageBytes), triageTightBudget)
	}
}

func budgetVerdict(n, budget int) string {
	if n < budget {
		return "OK"
	}
	return "OVER"
}
