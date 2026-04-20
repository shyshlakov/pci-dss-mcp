package scriptscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
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

// hasRulePrefix reports whether any finding's RuleID starts with the given
// prefix. scriptscanner emits both SRI-MISSING and SRI-MISSING-PAYMENT; this
// helper keeps integration tests tolerant to the suffix variant.
func hasRulePrefix(out *scanner.ScannerToolOutput, prefix string) bool {
	if out == nil {
		return false
	}
	for _, f := range out.Findings {
		if len(f.RuleID) >= len(prefix) && f.RuleID[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}

// setupIntegrationServer creates a server with check_payment_page_scripts
// registered, connects an in-memory client, and returns the client session.
func setupIntegrationServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-integration", Version: "v0.0.1"}, nil)
	scriptscanner.RegisterTools(server)

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

// copyFixture reads a file from testdata/ and writes it to dstDir with the same base name.
func copyFixture(t *testing.T, fixturePath, dstDir string) {
	t.Helper()
	srcBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", fixturePath, err)
	}
	dstPath := filepath.Join(dstDir, filepath.Base(fixturePath))
	if err := os.WriteFile(dstPath, srcBytes, 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", dstPath, err)
	}
}

// TestIntegration_GoCSPFindings verifies the full MCP round-trip for Go CSP
// violations: CSP-MISSING, CSP-UNSAFE-INLINE, CSP-UNSAFE-EVAL.
func TestIntegration_GoCSPFindings(t *testing.T) {
	session := setupIntegrationServer(t)

	fixtureSrc := filepath.Join("..", "..", "testdata", "script_violations.go")
	if _, err := os.Stat(fixtureSrc); err != nil {
		t.Skip("testdata/script_violations.go not found, skipping")
	}

	tmpDir := t.TempDir()
	copyFixture(t, fixtureSrc, tmpDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_payment_page_scripts",
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
	if !out.HasRuleID("CSP-MISSING") {
		t.Errorf("Expected CSP-MISSING in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("CSP-UNSAFE-INLINE") {
		t.Errorf("Expected CSP-UNSAFE-INLINE in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("CSP-UNSAFE-EVAL") {
		t.Errorf("Expected CSP-UNSAFE-EVAL in findings, got: %+v", out.Findings)
	}
	if !out.HasRequirementID("6.4.3") {
		t.Errorf("Expected requirement 6.4.3 in findings, got: %+v", out.Findings)
	}
	if !out.HasSeverity(scanner.SeverityHigh) && !out.HasSeverity(scanner.SeverityCritical) {
		t.Errorf("Expected HIGH or CRITICAL findings, got stats: %+v", out.SeverityStats)
	}
}

// TestIntegration_HTMLFindings verifies the full MCP round-trip for HTML
// template violations: SRI-MISSING, NONCE-MISSING, FIM-REQUIRED.
func TestIntegration_HTMLFindings(t *testing.T) {
	session := setupIntegrationServer(t)

	fixtureSrc := filepath.Join("..", "..", "testdata", "script_violations.html")
	if _, err := os.Stat(fixtureSrc); err != nil {
		t.Skip("testdata/script_violations.html not found, skipping")
	}

	tmpDir := t.TempDir()
	copyFixture(t, fixtureSrc, tmpDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_payment_page_scripts",
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
	if !hasRulePrefix(out, "SRI-MISSING") {
		t.Errorf("Expected SRI-MISSING in findings, got: %+v", out.Findings)
	}
	if !hasRulePrefix(out, "NONCE-MISSING") {
		t.Errorf("Expected NONCE-MISSING in findings, got: %+v", out.Findings)
	}
	if !out.HasRuleID("FIM-REQUIRED") {
		t.Errorf("Expected FIM-REQUIRED in findings, got: %+v", out.Findings)
	}
	if !out.HasSeverity(scanner.SeverityCritical) {
		t.Errorf("Expected CRITICAL findings, got stats: %+v", out.SeverityStats)
	}
}

// TestIntegration_CombinedScan verifies that scanning a directory with both Go
// and HTML violations returns findings from both in a single response.
func TestIntegration_CombinedScan(t *testing.T) {
	session := setupIntegrationServer(t)

	goFixture := filepath.Join("..", "..", "testdata", "script_violations.go")
	htmlFixture := filepath.Join("..", "..", "testdata", "script_violations.html")
	if _, err := os.Stat(goFixture); err != nil {
		t.Skip("testdata/script_violations.go not found, skipping")
	}
	if _, err := os.Stat(htmlFixture); err != nil {
		t.Skip("testdata/script_violations.html not found, skipping")
	}

	tmpDir := t.TempDir()
	copyFixture(t, goFixture, tmpDir)
	copyFixture(t, htmlFixture, tmpDir)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_payment_page_scripts",
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
	if !out.HasRuleID("CSP-MISSING") {
		t.Errorf("Expected CSP-MISSING (from Go scan) in combined findings, got: %+v", out.Findings)
	}
	if !hasRulePrefix(out, "SRI-MISSING") {
		t.Errorf("Expected SRI-MISSING (from HTML scan) in combined findings, got: %+v", out.Findings)
	}
	if !out.HasFilePathContains("script_violations.go") {
		t.Errorf("Expected script_violations.go in findings, got: %+v", out.Findings)
	}
	if !out.HasFilePathContains("script_violations.html") {
		t.Errorf("Expected script_violations.html in findings, got: %+v", out.Findings)
	}
}

// TestIntegration_CleanDirectory verifies that scanning a directory with no
// violations returns "No violations found."
func TestIntegration_CleanDirectory(t *testing.T) {
	session := setupIntegrationServer(t)

	// Create a clean Go file with a non-payment handler.
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
		Name: "check_payment_page_scripts",
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
		Name: "check_payment_page_scripts",
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
