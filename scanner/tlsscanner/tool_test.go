package tlsscanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/tlsscanner"
)

// parseStructured re-marshals result.StructuredContent (delivered as a
// map[string]any on the client side after JSON-RPC transport) into a typed
// ScannerToolOutput.: single-scanner tools return typed output via the
// MCP SDK's structured-content channel instead of text blobs.
func parseStructured(t *testing.T, result *mcp.CallToolResult) *scanner.ScannerToolOutput {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatalf("CallToolResult.StructuredContent is nil; summary text: %s", extractText(t, result))
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var out scanner.ScannerToolOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal StructuredContent: %v\nraw: %s", err, string(raw))
	}
	return &out
}

// setupTestServer creates a server with check_tls_config registered,
// connects an in-memory client, and returns the client session.
func setupTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-test", Version: "v0.0.1"}, nil)
	tlsscanner.RegisterTools(server)

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

func TestToolRegistered(t *testing.T) {
	t.Parallel()
	session := setupTestServer(t)

	result, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range result.Tools {
		if tool.Name == "check_tls_config" {
			found = true
			if tool.Description == "" {
				t.Error("check_tls_config tool should have a non-empty description")
			}
			break
		}
	}
	if !found {
		t.Error("check_tls_config tool should be registered in the server")
	}
}

func TestToolValidPath_WithViolations(t *testing.T) {
	t.Parallel()
	session := setupTestServer(t)

	// Create temp directory with a Go file containing TLS violations.
	tmpDir := t.TempDir()
	violationFile := filepath.Join(tmpDir, "insecure.go")
	content := `package test
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: true}
`
	if err := os.WriteFile(violationFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_tls_config",
		Arguments: map[string]any{
			"path":          tmpDir,
			"include_tests": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseStructured(t, result)
	if out.SeverityStats.Critical == 0 {
		t.Errorf("Expected CRITICAL finding, got stats: %+v", out.SeverityStats)
	}
	var sawSkipVerify, sawMissingMin bool
	for _, f := range out.Findings {
		if strings.Contains(f.Description, "InsecureSkipVerify") {
			sawSkipVerify = true
		}
		if f.RuleID == "TLS-MISSING-MIN-VERSION" && f.Severity == scanner.SeverityHigh {
			sawMissingMin = true
		}
	}
	if !sawSkipVerify {
		t.Errorf("Expected finding to mention InsecureSkipVerify, got: %+v", out.Findings)
	}
	if !sawMissingMin {
		t.Errorf("Expected TLS-MISSING-MIN-VERSION HIGH finding, got: %+v", out.Findings)
	}
}

func TestToolInvalidPath(t *testing.T) {
	t.Parallel()
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_tls_config",
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
	t.Parallel()
	session := setupTestServer(t)

	// Create temp directory with a Go file containing violations.
	tmpDir := t.TempDir()
	violationFile := filepath.Join(tmpDir, "insecure.go")
	content := `package test
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: true}
`
	if err := os.WriteFile(violationFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Exclude all.go files -- should find nothing.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_tls_config",
		Arguments: map[string]any{
			"path":             tmpDir,
			"exclude_patterns": []any{"*.go"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseStructured(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings when all Go files excluded, got %d: %+v", len(out.Findings), out.Findings)
	}
}

func TestToolCleanCode(t *testing.T) {
	t.Parallel()
	session := setupTestServer(t)

	// Create temp directory with clean TLS code.
	tmpDir := t.TempDir()
	cleanFile := filepath.Join(tmpDir, "secure.go")
	content := `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS12}
`
	if err := os.WriteFile(cleanFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_tls_config",
		Arguments: map[string]any{
			"path": tmpDir,
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseStructured(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings for secure code, got %d: %+v", len(out.Findings), out.Findings)
	}
}
