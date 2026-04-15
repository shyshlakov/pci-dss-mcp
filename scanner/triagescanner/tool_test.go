package triagescanner_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

// decodeTriageStructured deserializes the StructuredContent payload returned
// by triage_findings into a typed TriageResult. Per MCP spec 2025-06-18, the
// SDK marshals the typed Out value into CallToolResult.StructuredContent.
// On the client side after the JSON-RPC round-trip the field surfaces as a
// generic map[string]any (or json.RawMessage when the SDK skips decoding),
// so the helper handles both shapes by re-marshaling through json.Marshal.
func decodeTriageStructured(t *testing.T, result *mcp.CallToolResult) *triagescanner.TriageResult {
	t.Helper()
	if result == nil || result.StructuredContent == nil {
		t.Fatal("CallToolResult.StructuredContent is nil; expected typed Out value")
	}
	var raw []byte
	switch v := result.StructuredContent.(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal StructuredContent (%T): %v", v, err)
		}
		raw = b
	}
	var tr triagescanner.TriageResult
	if err := json.Unmarshal(raw, &tr); err != nil {
		t.Fatalf("unmarshal StructuredContent: %v", err)
	}
	return &tr
}

func setupTriageServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New() error: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "triage-integration", Version: "v0.0.1"}, nil)
	triagescanner.RegisterTools(server, db)

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

func extractTriageText(t *testing.T, result *mcp.CallToolResult) string {
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

// copyFixtures copies all_violations.* files from testdata/ to a temp directory
// to bypass DefaultExcludeDirs "testdata" exclusion.
func copyFixtures(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()

	// Resolve testdata relative to this test file's package location.
	fixtureDir := filepath.Join("..", "..", "testdata")

	fixtures := []string{
		"all_violations.go",
		"all_violations.html",
		"all_violations.env",
		"all_violations.json",
		"all_violations.yaml",
	}

	for _, f := range fixtures {
		src := filepath.Join(fixtureDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", f, err)
		}
		dst := filepath.Join(tmpDir, f)
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("failed to write fixture %s: %v", f, err)
		}
	}

	return tmpDir
}

func TestTriageToolIntegration_WithViolations(t *testing.T) {
	session := setupTriageServer(t)
	tmpDir := copyFixtures(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "triage_findings",
		Arguments: map[string]any{"path": tmpDir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", extractTriageText(t, result))
	}

	// 1-line text summary only; no hybrid text+JSON dump.
	text := extractTriageText(t, result)
	if !strings.Contains(text, "findings triaged") {
		t.Errorf("text summary should contain 'findings triaged', got: %q", text)
	}
	if strings.Contains(text, "JSON:") {
		t.Errorf("text content must not contain hybrid 'JSON:' suffix, got: %q", text)
	}

	// structured payload carries the enriched findings.
	tr := decodeTriageStructured(t, result)
	if tr.Metadata.FindingsTotal == 0 {
		t.Fatal("StructuredContent: expected at least one triaged finding")
	}
	if len(tr.Findings) == 0 {
		t.Fatal("StructuredContent: Findings slice is empty")
	}

	// Verify enriched finding evidence is present (triage hint + severity).
	hasHint := false
	hasSeverity := false
	for _, ef := range tr.Findings {
		if ef.Hint != "" {
			hasHint = true
		}
		switch ef.Finding.Severity {
		case "CRITICAL", "HIGH", "MEDIUM":
			hasSeverity = true
		}
	}
	if !hasHint {
		t.Error("StructuredContent: expected at least one finding with a triage hint")
	}
	if !hasSeverity {
		t.Error("StructuredContent: expected at least one CRITICAL/HIGH/MEDIUM finding")
	}

	// every finding must carry a ResourceLink instead of inline source.
	for i, ef := range tr.Findings {
		if len(ef.Context.Sources) == 0 {
			t.Errorf("finding[%d]: expected Sources []ResourceLink, got 0 entries", i)
			continue
		}
		src := ef.Context.Sources[0]
		if !strings.HasPrefix(src.URI, "file://") {
			t.Errorf("finding[%d]: Source URI should be file://, got %q", i, src.URI)
		}
	}
}

func TestTriageToolIntegration_CleanProject(t *testing.T) {
	session := setupTriageServer(t)
	tmpDir := t.TempDir()

	// Create a clean Go file with no violations.
	content := []byte("package main\n\nfunc main() {}\n")
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), content, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "triage_findings",
		Arguments: map[string]any{"path": tmpDir},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %s", extractTriageText(t, result))
	}

	text := extractTriageText(t, result)
	if !strings.Contains(text, "No active findings to triage") {
		t.Errorf("clean project should return 'No active findings to triage', got: %s", text)
	}
}

func TestTriageToolIntegration_DefaultPath(t *testing.T) {
	session := setupTriageServer(t)

	// Call with empty path -- should default to "." and not error.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "triage_findings",
		Arguments: map[string]any{"path": ""},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}

	// The tool should run without an IsError for empty path.
	// It may find findings in CWD or not, but it should not fail with "path required".
	if result.IsError {
		text := extractTriageText(t, result)
		if strings.Contains(text, "path") && strings.Contains(text, "required") {
			t.Error("empty path should default to '.', not return 'path required' error")
		}
	}
}

func TestTriageToolIntegration_InvalidDepMode(t *testing.T) {
	session := setupTriageServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "triage_findings",
		Arguments: map[string]any{"path": ".", "dep_scan_mode": "invalid"},
	})
	if err != nil {
		t.Fatalf("CallTool error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid dep_scan_mode")
	}

	text := extractTriageText(t, result)
	if !strings.Contains(text, "Invalid dep_scan_mode") {
		t.Errorf("error should mention 'Invalid dep_scan_mode', got: %s", text)
	}
}
