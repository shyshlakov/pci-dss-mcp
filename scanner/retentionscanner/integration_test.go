package retentionscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/retentionscanner"
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

// setupIntegrationServer creates a server with check_data_retention registered,
// connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-integration", Version: "v0.0.1"}, nil)
	retentionscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	// Start server in background.
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

// extractIntegrationText extracts the text from the first TextContent in a CallToolResult.
func extractIntegrationText(t *testing.T, result *mcp.CallToolResult) string {
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

// TestIntegration_RetentionFindings verifies the full MCP round-trip for
// data retention violations: calls check_data_retention via MCP client,
// validates that findings contain expected rule IDs and file references.
func TestIntegration_RetentionFindings(t *testing.T) {
	session := setupIntegrationServer(t)

	// Copy Go fixture to a temp dir (walker excludes "testdata" directories).
	goFixtureSrc := filepath.Join("..", "..", "testdata", "retention_violations.go")
	goBytes, err := os.ReadFile(goFixtureSrc)
	if err != nil {
		t.Skip("testdata/retention_violations.go not found, skipping")
	}

	// Copy config fixtures.
	yamlFixtureSrc := filepath.Join("..", "..", "testdata", "retention_config.yaml")
	yamlBytes, err := os.ReadFile(yamlFixtureSrc)
	if err != nil {
		t.Skip("testdata/retention_config.yaml not found, skipping")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "retention_violations.go"), goBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "retention_config.yaml"), yamlBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_data_retention",
		Arguments: map[string]any{
			"path": tmpDir,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractIntegrationText(t, result))
	}

	out := parseOut(t, result)

	if !out.HasRuleID("RET-REDIS-NO-TTL") {
		t.Errorf("Expected RET-REDIS-NO-TTL in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("RET-DB-SENSITIVE-STORE") {
		t.Errorf("Expected RET-DB-SENSITIVE-STORE in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("RET-CONFIG-NO-TTL") {
		t.Errorf("Expected RET-CONFIG-NO-TTL in findings, got: %+v", out.Findings)
	}
	if !out.HasRequirementID("3.2.1") {
		t.Errorf("Expected RequirementID 3.2.1 in findings, got: %+v", out.Findings)
	}
	if !out.HasSeverity(scanner.SeverityCritical) {
		t.Errorf("Expected CRITICAL findings, got stats: %+v", out.SeverityStats)
	}
	if !out.HasFilePathContains("retention_violations.go") {
		t.Errorf("Expected findings to mention retention_violations.go, got: %+v", out.Findings)
	}
}

// TestIntegration_CleanDirectory verifies that scanning a directory with no
// retention violations returns zero findings.
func TestIntegration_CleanDirectory(t *testing.T) {
	session := setupIntegrationServer(t)

	tmpDir := t.TempDir()
	content := `package test

import "net/http"

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "health.go"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_data_retention",
		Arguments: map[string]any{
			"path": tmpDir,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractIntegrationText(t, result))
	}

	out := parseOut(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings for clean directory, got %d: %+v", len(out.Findings), out.Findings)
	}
}

// TestIntegration_InvalidPath verifies the MCP round-trip returns IsError=true
// for a nonexistent path.
func TestIntegration_InvalidPath(t *testing.T) {
	session := setupIntegrationServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_data_retention",
		Arguments: map[string]any{
			"path": "/nonexistent/integration/test/path",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for non-existent path")
	}
}
