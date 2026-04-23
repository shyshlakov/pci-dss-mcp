package auditscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner/auditscanner"
)

// setupTestServer creates a server with audit_log_coverage registered,
// connects an in-memory client, and returns the client session.
func setupTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-test", Version: "v0.0.1"}, nil)
	auditscanner.RegisterTools(server)

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

// extractToolText extracts the text from the first TextContent in a CallToolResult.
func extractToolText(t *testing.T, result *mcp.CallToolResult) string {
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

func TestToolRegistered(t *testing.T) {
	session := setupTestServer(t)

	result, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range result.Tools {
		if tool.Name == "audit_log_coverage" {
			found = true
			if tool.Description == "" {
				t.Error("audit_log_coverage tool should have a non-empty description")
			}
			if !strings.Contains(tool.Description, "PCI DSS 10.2.1") {
				t.Error("audit_log_coverage tool description should mention PCI DSS 10.2.1")
			}
			break
		}
	}
	if !found {
		t.Error("audit_log_coverage tool should be registered in the server")
	}
}

func TestToolValidPath(t *testing.T) {
	session := setupTestServer(t)

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
		t.Fatalf("Expected success, got IsError=true: %s", extractToolText(t, result))
	}

	out := parseOut(t, result)
	if out.SeverityStats.Critical+out.SeverityStats.High == 0 {
		t.Errorf("Expected CRITICAL or HIGH findings, got stats: %+v", out.SeverityStats)
	}
	if !out.HasRuleID("AUDIT-NO-LOG") {
		t.Errorf("Expected AUDIT-NO-LOG in findings, got: %+v", out.Findings)
	}
}

func TestToolInvalidPath(t *testing.T) {
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "audit_log_coverage",
		Arguments: map[string]any{
			"path": "/nonexistent/path/that/does/not/exist",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for non-existent path")
	}
}

func TestToolExcludePatterns(t *testing.T) {
	session := setupTestServer(t)

	// Copy fixture to a temp dir.
	fixtureSrc := filepath.Join("..", "..", "testdata", "audit_violations.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/audit_violations.go not found, skipping")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "audit_violations.go"), srcBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Exclude all.go files -- should find nothing.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "audit_log_coverage",
		Arguments: map[string]any{
			"path":             tmpDir,
			"exclude_patterns": []any{"*.go"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractToolText(t, result))
	}

	out := parseOut(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings when all Go files excluded, got %d: %+v", len(out.Findings), out.Findings)
	}
}
