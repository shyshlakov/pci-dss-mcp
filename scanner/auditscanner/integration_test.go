package auditscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/auditscanner"
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

// setupIntegrationServer creates a server with audit_log_coverage registered,
// connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-integration", Version: "v0.0.1"}, nil)
	auditscanner.RegisterTools(server)

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

// TestIntegration_AuditLogFindings verifies the full MCP round-trip for audit
// log violations: calls audit_log_coverage via MCP client, validates that
// findings contain expected rule IDs and file references.
func TestIntegration_AuditLogFindings(t *testing.T) {
	session := setupIntegrationServer(t)

	// Copy fixture to a temp dir (walker excludes "testdata" directories).
	fixtureSrc := filepath.Join("..", "..", "testdata", "audit_violations.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/audit_violations.go not found, skipping")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "audit_violations.go"), srcBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "audit_log_coverage",
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

	if !out.HasRuleID("AUDIT-NO-LOG") {
		t.Errorf("Expected AUDIT-NO-LOG in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("AUDIT-UNSTRUCTURED") {
		t.Errorf("Expected AUDIT-UNSTRUCTURED in findings, got: %+v", out.Findings)
	}
	if !out.HasRequirementID("10.2.1") {
		t.Errorf("Expected RequirementID 10.2.1 in findings, got: %+v", out.Findings)
	}
	if !out.HasFilePathContains("audit_violations.go") {
		t.Errorf("Expected findings to mention audit_violations.go, got: %+v", out.Findings)
	}
	// Any non-INFO severity (HIGH/CRITICAL) is acceptable — fixture mixes both.
	if out.SeverityStats.Critical+out.SeverityStats.High == 0 {
		t.Errorf("Expected CRITICAL or HIGH findings, got stats: %+v", out.SeverityStats)
	}
}

// TestIntegration_CleanDirectory verifies that scanning a directory with no
// payment handlers returns zero findings.
func TestIntegration_CleanDirectory(t *testing.T) {
	session := setupIntegrationServer(t)

	// Create a clean Go file with no payment handlers.
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
		Name: "audit_log_coverage",
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
		t.Errorf("Expected 0 findings for clean directory, got %d: %+v", len(out.Findings), out.Findings)
	}
}

// TestIntegration_InvalidPath verifies the MCP round-trip returns IsError=true
// for a nonexistent path.
func TestIntegration_InvalidPath(t *testing.T) {
	session := setupIntegrationServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "audit_log_coverage",
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
