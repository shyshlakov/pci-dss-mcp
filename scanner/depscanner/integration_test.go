package depscanner_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/depscanner"
)

// parseOut is the shared typed-output parser for MCP tool tests.
func parseOut(t *testing.T, result *mcp.CallToolResult) *scanner.ScannerToolOutput {
	t.Helper()
	out, err := scanner.ParseScannerToolOutput(result)
	if err != nil {
		t.Fatalf("ParseScannerToolOutput: %v", err)
	}
	return out
}

// parseUpdateDBOut re-marshals StructuredContent into the typed update_vulnerability_db output.
func parseUpdateDBOut(t *testing.T, result *mcp.CallToolResult) *depscanner.UpdateDBOutput {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatal("update_vulnerability_db: StructuredContent is nil")
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var out depscanner.UpdateDBOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal UpdateDBOutput: %v\nraw: %s", err, string(raw))
	}
	return &out
}

// setupIntegrationServer creates a server with both dep scanner tools registered,
// connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "depscanner-integration", Version: "v0.0.1"}, nil)
	depscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	go func() {
		if err := server.Run(context.Background(), serverTransport); err != nil {
			return
		}
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() failed: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return session
}

// extractText extracts the text from the first TextContent in a CallToolResult.
func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("CallToolResult has no content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("Expected TextContent, got %T", result.Content[0])
	}
	return tc.Text
}

// buildTestCache creates a minimal OSV cache JSON file at the given path.
func buildTestCache(t *testing.T, cacheDir string, cacheDate time.Time, vulns map[string][]json.RawMessage) {
	t.Helper()

	dateStr := cacheDate.Format("2006-01-02")
	cachePath := filepath.Join(cacheDir, fmt.Sprintf("go-osv-%s.json", dateStr))

	cache := map[string]any{
		"generated":  cacheDate.UTC(),
		"source":     "test",
		"vuln_count": 0,
		"packages":   vulns,
	}

	// Count vulns.
	count := 0
	for _, v := range vulns {
		count += len(v)
	}
	cache["vuln_count"] = count

	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal test cache: %v", err)
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("create cache dir: %v", err)
	}

	if err := os.WriteFile(cachePath, data, 0o644); err != nil {
		t.Fatalf("write test cache: %v", err)
	}
}

// vulnJSON builds a raw JSON vulnerability entry for test cache construction.
func vulnJSON(id, pkg, introduced, fixed string) json.RawMessage {
	v := map[string]any{
		"id":      id,
		"summary": fmt.Sprintf("Test vulnerability %s", id),
		"aliases": []string{},
		"database_specific": map[string]string{
			"severity": "HIGH",
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
							{"introduced": introduced},
							{"fixed": fixed},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(v)
	return data
}

// copyGoMod copies the vulnerable go.mod fixture to a temp directory.
func copyGoMod(t *testing.T, dstDir string) {
	t.Helper()
	srcPath := filepath.Join("..", "..", "testdata", "vulnerable.go.mod")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", srcPath, err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "go.mod"), data, 0o644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}
}

// createTestZIP builds an in-memory ZIP containing OSV vulnerability JSON entries.
func createTestZIP(vulns map[string]any) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, vuln := range vulns {
		data, _ := json.Marshal(vuln)
		f, _ := w.Create(name)
		f.Write(data)
	}
	w.Close()
	return buf.Bytes()
}

func TestIntegrationToolsListed(t *testing.T) {
	session := setupIntegrationServer(t)

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	foundCheckDeps := false
	foundUpdateDB := false
	for _, tool := range tools.Tools {
		switch tool.Name {
		case "check_dependencies":
			foundCheckDeps = true
		case "update_vulnerability_db":
			foundUpdateDB = true
		}
	}
	if !foundCheckDeps {
		t.Error("check_dependencies not found in ListTools")
	}
	if !foundUpdateDB {
		t.Error("update_vulnerability_db not found in ListTools")
	}
}

func TestIntegrationCheckDepsOfflineWithCache(t *testing.T) {
	session := setupIntegrationServer(t)

	// Create temp project dir with vulnerable go.mod.
	projectDir := t.TempDir()
	copyGoMod(t, projectDir)

	// Create cache with known vuln for golang.org/x/net.
	cacheDir := t.TempDir()
	vulns := map[string][]json.RawMessage{
		"golang.org/x/net": {
			vulnJSON("GHSA-test-1234", "golang.org/x/net", "0", "0.23.0"),
		},
	}
	buildTestCache(t, cacheDir, time.Now(), vulns)

	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": projectDir,
			"mode": "offline",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseOut(t, result)
	if len(out.Findings) == 0 {
		t.Fatal("Expected at least one vulnerability finding")
	}
	sawGHSA := false
	sawXNet := false
	for _, f := range out.Findings {
		if strings.Contains(f.Description, "GHSA") {
			sawGHSA = true
		}
		if strings.Contains(f.Description, "golang.org/x/net") {
			sawXNet = true
		}
	}
	if !sawGHSA {
		t.Errorf("Expected GHSA in finding descriptions, got: %+v", out.Findings)
	}
	if !sawXNet {
		t.Errorf("Expected golang.org/x/net in finding descriptions, got: %+v", out.Findings)
	}
	if !out.HasRequirementID("6.3.3") {
		t.Errorf("Expected requirement 6.3.3 in findings, got: %+v", out.Findings)
	}
	if out.SeverityStats.Critical+out.SeverityStats.High+out.SeverityStats.Medium+out.SeverityStats.Low == 0 {
		t.Errorf("Expected a non-INFO severity on findings, got stats: %+v", out.SeverityStats)
	}
}

func TestIntegrationCheckDepsOfflineNoCache(t *testing.T) {
	session := setupIntegrationServer(t)

	// Empty cache dir -- no cache files.
	cacheDir := t.TempDir()
	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	projectDir := t.TempDir()
	copyGoMod(t, projectDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": projectDir,
			"mode": "offline",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for missing cache")
	}

	text := extractText(t, result)

	if !strings.Contains(text, "action_required") {
		t.Errorf("Expected 'action_required' in error, got:\n%s", text)
	}
	if !strings.Contains(text, "update_vulnerability_db") {
		t.Errorf("Expected 'update_vulnerability_db' in error, got:\n%s", text)
	}
	if !strings.Contains(text, "pci_impact") {
		t.Errorf("Expected 'pci_impact' in error, got:\n%s", text)
	}
}

func TestIntegrationCheckDepsInvalidMode(t *testing.T) {
	session := setupIntegrationServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": t.TempDir(),
			"mode": "invalid_mode",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for invalid mode")
	}

	text := extractText(t, result)
	if !strings.Contains(text, "Invalid mode") {
		t.Errorf("Expected 'Invalid mode' in error, got:\n%s", text)
	}
}

func TestIntegrationCheckDepsCleanProject(t *testing.T) {
	session := setupIntegrationServer(t)

	// Create a go.mod with deps that have no vulns in our cache.
	projectDir := t.TempDir()
	goModContent := `module example.com/clean-app

go 1.21

require (
	github.com/clean/package v1.5.0
)
`
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte(goModContent), 0o644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}

	// Create cache with vulns that do NOT match the clean deps.
	cacheDir := t.TempDir()
	vulns := map[string][]json.RawMessage{
		"golang.org/x/net": {
			vulnJSON("GHSA-test-9999", "golang.org/x/net", "0", "0.23.0"),
		},
	}
	buildTestCache(t, cacheDir, time.Now(), vulns)

	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": projectDir,
			"mode": "offline",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseOut(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings for clean project, got %d: %+v", len(out.Findings), out.Findings)
	}
}

func TestIntegrationUpdateVulnDB(t *testing.T) {
	// Create a mock HTTP server serving a test ZIP.
	goVuln := map[string]any{
		"id":      "GHSA-test-mock",
		"summary": "Mock vuln for integration test",
		"affected": []map[string]any{
			{
				"package": map[string]string{
					"name":      "golang.org/x/net",
					"ecosystem": "Go",
				},
				"ranges": []map[string]any{
					{
						"type":   "SEMVER",
						"events": []map[string]string{{"introduced": "0"}, {"fixed": "0.23.0"}},
					},
				},
			},
		},
	}

	zipData := createTestZIP(map[string]any{
		"GHSA-test-mock.json": goVuln,
	})

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer mockServer.Close()

	// Override the OSV ZIP URL to point to our mock server.
	restore := depscanner.SetOSVZipURL(mockServer.URL)
	defer restore()

	session := setupIntegrationServer(t)

	outputDir := t.TempDir()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "update_vulnerability_db",
		Arguments: map[string]any{
			"output_path": outputDir,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseUpdateDBOut(t, result)
	if out.VulnCount == 0 {
		t.Error("Expected VulnCount > 0 after successful update")
	}
	if out.CachePath == "" {
		t.Error("Expected non-empty CachePath")
	}
	if !strings.HasPrefix(filepath.Base(out.CachePath), "go-osv-") {
		t.Errorf("Expected cache file with go-osv- prefix, got %q", out.CachePath)
	}

	// Verify cache file was created.
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "go-osv-") && strings.HasSuffix(e.Name(), ".json") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected cache file go-osv-*.json in output directory")
	}
}

func TestIntegrationCheckDepsStaleCacheWarning(t *testing.T) {
	session := setupIntegrationServer(t)

	projectDir := t.TempDir()
	copyGoMod(t, projectDir)

	// Create cache dated 10 days ago.
	cacheDir := t.TempDir()
	staleDate := time.Now().AddDate(0, 0, -10)
	vulns := map[string][]json.RawMessage{
		"golang.org/x/net": {
			vulnJSON("GHSA-stale-1234", "golang.org/x/net", "0", "0.23.0"),
		},
	}
	buildTestCache(t, cacheDir, staleDate, vulns)

	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": projectDir,
			"mode": "offline",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseOut(t, result)
	sawWarning := false
	for _, f := range out.Findings {
		if strings.Contains(f.Suggestion, "update_vulnerability_db") ||
			strings.Contains(f.Description, "update_vulnerability_db") {
			sawWarning = true
			break
		}
	}
	if !sawWarning {
		t.Errorf("Expected stale cache warning mentioning update_vulnerability_db, got: %+v", out.Findings)
	}
}
