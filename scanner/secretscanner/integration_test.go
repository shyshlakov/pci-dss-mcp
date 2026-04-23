package secretscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
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

// setupIntegrationServer creates a server with check_secrets_in_configs registered,
// connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-integration", Version: "v0.0.1"}, nil)
	secretscanner.RegisterTools(server)

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

// copyFixtures copies the specified fixture files from testdata/ to a temp directory.
func copyFixtures(t *testing.T, files []string) string {
	t.Helper()
	fixtureDir := filepath.Join("..", "..", "testdata")
	tmpDir := t.TempDir()
	for _, f := range files {
		src := filepath.Join(fixtureDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Skipf("fixture %s not found, skipping: %v", f, err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, f), data, 0644); err != nil {
			t.Fatalf("WriteFile %s: %v", f, err)
		}
	}
	return tmpDir
}

// TestIntegration_AllFormats verifies the secrets scanner catches violations across
// all four file formats (.env,.yaml,.json,.toml) in a single scan via MCP round-trip.
func TestIntegration_AllFormats(t *testing.T) {
	t.Parallel()
	session := setupIntegrationServer(t)

	tmpDir := copyFixtures(t, []string{"secrets.env", "secrets.yaml", "secrets.json", "secrets.toml"})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
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
	if !out.HasSeverity(scanner.SeverityCritical) {
		t.Errorf("Expected CRITICAL findings, got stats: %+v", out.SeverityStats)
	}
	secIDs := []string{"SEC-PREFIX", "SEC-CONNSTR", "SEC-CREDENTIAL-KEY", "SEC-HIGH-ENTROPY"}
	hasSEC := false
	for _, id := range secIDs {
		if out.HasRuleID(id) {
			hasSEC = true
			break
		}
	}
	if !hasSEC {
		t.Errorf("Expected SEC- rule ID in findings, got: %+v", out.Findings)
	}
	for _, f := range []string{"secrets.env", "secrets.yaml", "secrets.json", "secrets.toml"} {
		if !out.HasFilePathContains(f) {
			t.Errorf("Expected findings to mention file %q, got: %+v", f, out.Findings)
		}
	}
}

// TestIntegration_RuleIDPrefix verifies that every finding has a SEC- prefixed rule ID.
func TestIntegration_RuleIDPrefix(t *testing.T) {
	t.Parallel()
	session := setupIntegrationServer(t)

	// Use a single fixture with known violations.
	tmpDir := copyFixtures(t, []string{"secrets.env"})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
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
	if len(out.Findings) == 0 {
		t.Fatal("Expected at least one finding from secrets.env")
	}
	for _, f := range out.Findings {
		if !strings.HasPrefix(f.RuleID, "SEC-") {
			t.Errorf("Expected RuleID to start with SEC-, got %q", f.RuleID)
		}
	}
}

// TestIntegration_InvalidPath verifies the MCP round-trip returns IsError=true
// for a nonexistent path.
func TestIntegration_InvalidPath(t *testing.T) {
	t.Parallel()
	session := setupIntegrationServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
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

// TestIntegration_CleanFile verifies that scanning a directory with only clean
// config files returns "No violations found."
func TestIntegration_CleanFile(t *testing.T) {
	t.Parallel()
	session := setupIntegrationServer(t)

	tmpDir := copyFixtures(t, []string{"secrets_clean.env"})

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
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
		t.Errorf("Expected 0 findings for clean config, got %d: %+v", len(out.Findings), out.Findings)
	}
}
