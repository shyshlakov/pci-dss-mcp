package errorscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/errorscanner"
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

// setupIntegrationServer creates a server with check_error_handling registered,
// connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-integration", Version: "v0.0.1"}, nil)
	errorscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	// Start server in background.
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })

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

// TestIntegration_ErrorLeakFindings verifies the full MCP round-trip for error
// handling violations: calls check_error_handling via MCP client, validates
// that findings contain expected rule IDs and file references.
func TestIntegration_ErrorLeakFindings(t *testing.T) {
	session := setupIntegrationServer(t)

	// Copy fixture to a temp dir (walker excludes "testdata" directories).
	fixtureSrc := filepath.Join("..", "..", "testdata", "error_violations.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/error_violations.go not found, skipping")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "error_violations.go"), srcBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_error_handling",
		Arguments: map[string]any{
			"path":          tmpDir,
			"include_tests": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractIntegrationText(t, result))
	}

	out := parseOut(t, result)

	if out.SeverityStats.Critical+out.SeverityStats.High == 0 {
		t.Errorf("Expected CRITICAL or HIGH findings, got stats: %+v", out.SeverityStats)
	}

	errLeakRules := []string{"ERR-LEAK-DIRECT", "ERR-LEAK-FORMAT", "ERR-LEAK-WRITE", "ERR-LEAK-ENCODE"}
	for _, rule := range errLeakRules {
		if !out.HasRuleID(rule) {
			t.Errorf("Expected %s in findings, got: %+v", rule, out.Findings)
		}
	}

	if !out.HasFilePathContains("error_violations.go") {
		t.Errorf("Expected findings to mention error_violations.go, got: %+v", out.Findings)
	}
}

// TestIntegration_InvalidPath verifies the MCP round-trip returns IsError=true
// for a nonexistent path.
func TestIntegration_InvalidPath(t *testing.T) {
	session := setupIntegrationServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_error_handling",
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

// TestIntegration_NonPaymentHandlerSkipped verifies that the scanner skips
// non-payment handler functions (no false positives on generic handlers).
func TestIntegration_NonPaymentHandlerSkipped(t *testing.T) {
	session := setupIntegrationServer(t)

	// Create a Go file with only non-payment handlers that use err.Error().
	tmpDir := t.TempDir()
	content := `package test

import (
	"net/http"
)

// Non-payment handler -- should not trigger findings.
func HandleHealth(w http.ResponseWriter, r *http.Request) {
	err := checkHealth()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func checkHealth() error { return nil }
`
	if err := os.WriteFile(filepath.Join(tmpDir, "health.go"), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_error_handling",
		Arguments: map[string]any{
			"path":          tmpDir,
			"include_tests": true,
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
		t.Errorf("Expected 0 findings for non-payment handler, got %d: %+v", len(out.Findings), out.Findings)
	}
}
