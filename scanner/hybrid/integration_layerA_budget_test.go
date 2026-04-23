package hybrid_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func newAllToolsSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "layera-budget", Version: "v0.0.1"}, nil)
	auditscanner.RegisterTools(server)
	authscanner.RegisterTools(server)
	cryptoscanner.RegisterTools(server)
	depscanner.RegisterTools(server)
	errorscanner.RegisterTools(server)
	panscanner.RegisterTools(server)
	reportscanner.RegisterTools(server, db)
	retentionscanner.RegisterTools(server)
	scriptscanner.RegisterTools(server)
	secretscanner.RegisterTools(server)
	tlsscanner.RegisterTools(server)
	triagescanner.RegisterTools(server, db)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "layera-budget-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func seedDepFixtureForBudget(t *testing.T) string {
	t.Helper()
	projectDir := t.TempDir()
	srcGoMod := filepath.Join("..", "..", "testdata", "vulnerable.go.mod")
	data, err := os.ReadFile(srcGoMod)
	if err != nil {
		t.Fatalf("read go.mod fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), data, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	cacheDir := t.TempDir()
	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
	now := time.Now()
	datePath := filepath.Join(cacheDir, fmt.Sprintf("go-osv-%s.json", now.Format("2006-01-02")))
	vulnRaw := func(id, pkg, sev string) json.RawMessage {
		v := map[string]any{
			"id":      id,
			"summary": fmt.Sprintf("Test vulnerability %s", id),
			"aliases": []string{},
			"database_specific": map[string]string{
				"severity": sev,
			},
			"affected": []map[string]any{
				{
					"package": map[string]string{
						"name":      pkg,
						"ecosystem": "Go",
					},
					"ranges": []map[string]any{
						{
							"type": "SEMVER",
							"events": []map[string]string{
								{"introduced": "0"},
								{"fixed": "99.0.0"},
							},
						},
					},
				},
			},
		}
		b, _ := json.Marshal(v)
		return b
	}
	cache := map[string]any{
		"generated":  now.UTC(),
		"source":     "test",
		"vuln_count": 2,
		"packages": map[string][]json.RawMessage{
			"golang.org/x/net":  {vulnRaw("GHSA-budget-net", "golang.org/x/net", "HIGH")},
			"golang.org/x/text": {vulnRaw("GHSA-budget-text", "golang.org/x/text", "HIGH")},
		},
	}
	cb, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(datePath, cb, 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	return projectDir
}

func TestAllLayerA_SizeBudget20KB(t *testing.T) {
	session := newAllToolsSession(t)
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	fixtureAbs, err := filepath.Abs(fixtureRoot)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	depFixture := seedDepFixtureForBudget(t)

	tt := []struct {
		name string
		args map[string]any
	}{
		{"check_auth_strength", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "HIGH"}},
		{"check_encryption", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_tls_config", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_secrets_in_configs", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_error_handling", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"audit_log_coverage", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_data_retention", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_payment_page_scripts", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "MEDIUM"}},
		{"check_dependencies", map[string]any{"path": depFixture, "mode": "offline", "min_severity": "HIGH"}},
		{"scan_pan_data", map[string]any{"path": fixtureAbs, "include_tests": true, "min_severity": "HIGH"}},
		{"triage_findings", map[string]any{"path": fixtureAbs, "dep_scan_mode": "offline", "include_taint": true, "min_severity": "HIGH"}},
		{"generate_compliance_report", map[string]any{"path": fixtureAbs, "dep_scan_mode": "offline", "include_taint": true, "min_severity": "MEDIUM"}},
	}

	const budget = 20480
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      tc.name,
				Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool %s: %v", tc.name, err)
			}
			if result.IsError {
				t.Fatalf("%s Layer A returned IsError: %+v", tc.name, result)
			}
			raw, err := json.Marshal(result.StructuredContent)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.name, err)
			}
			t.Logf("%s Layer A wire size = %d bytes (budget %d, headroom %d)", tc.name, len(raw), budget, budget-len(raw))
			if len(raw) >= budget {
				t.Errorf("%s Layer A wire size %d bytes exceeds budget %d", tc.name, len(raw), budget)
			}
		})
	}
}
