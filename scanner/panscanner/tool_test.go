package panscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
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

// setupTestServer creates a server with scan_pan_data registered,
// connects an in-memory client, and returns the client session.
func setupTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-test", Version: "v0.0.1"}, nil)
	panscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

	// Start server in background.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if err := server.Run(ctx, serverTransport); err != nil {
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

func TestScanPANData_ToolRegistered(t *testing.T) {
	session := setupTestServer(t)

	result, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range result.Tools {
		if tool.Name == "scan_pan_data" {
			found = true
			if tool.Description == "" {
				t.Error("scan_pan_data tool should have a non-empty description")
			}
			break
		}
	}
	if !found {
		t.Error("scan_pan_data tool should be registered in the server")
	}
}

func TestScanPANData_ValidPath(t *testing.T) {
	session := setupTestServer(t)

	// Create temp directory with a Go file containing a known violation.
	tmpDir := t.TempDir()
	violationFile := filepath.Join(tmpDir, "payment.go")
	content := `package test

type Payment struct {
	CardNumber string
	Amount     float64
	Currency   string
	Merchant   string
}
`
	if err := os.WriteFile(violationFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_pan_data",
		Arguments: map[string]any{
			"path":             tmpDir,
			"exclude_patterns": []any{"vendor/"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}

	out := parseOut(t, result)
	if out.SeverityStats.Critical+out.SeverityStats.High+out.SeverityStats.Medium == 0 {
		t.Errorf("Expected CRITICAL / HIGH / MEDIUM findings, got stats: %+v", out.SeverityStats)
	}
	if !out.HasDescriptionContains("CardNumber") && !out.HasDescriptionContains("cardNumber") {
		t.Errorf("Expected finding to mention CardNumber, got: %+v", out.Findings)
	}
}

func TestScanPANData_InvalidPath(t *testing.T) {
	session := setupTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_pan_data",
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

func TestScanPANData_CleanCode(t *testing.T) {
	session := setupTestServer(t)

	// Create temp directory with only clean code (no violations).
	tmpDir := t.TempDir()
	cleanFile := filepath.Join(tmpDir, "clean.go")
	content := `package test

type Request struct {
	ID     string
	Amount int
	Status string
}

func HandleRequest(id string) error {
	return nil
}
`
	if err := os.WriteFile(cleanFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_pan_data",
		Arguments: map[string]any{
			"path":             tmpDir,
			"exclude_patterns": []any{"vendor/"},
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
		t.Errorf("Expected 0 findings for clean code, got %d: %+v", len(out.Findings), out.Findings)
	}
}

func TestScanPANData_CustomExclude(t *testing.T) {
	session := setupTestServer(t)

	// Create temp directory with a Go file containing violations.
	tmpDir := t.TempDir()
	violationFile := filepath.Join(tmpDir, "payment.go")
	content := `package test

var cardNumber = "test"
`
	if err := os.WriteFile(violationFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Exclude all.go files -- should find nothing.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_pan_data",
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

	out := parseOut(t, result)
	if len(out.Findings) != 0 {
		t.Errorf("Expected 0 findings when all Go files excluded, got %d: %+v", len(out.Findings), out.Findings)
	}
}

// TestTool_IncludeTaintParam validates that ScanPANInput exposes the IncludeTaint
// field with the right jsonschema annotation (default false, mentions go/packages)
// and that the tool handler accepts the parameter without error.
func TestTool_IncludeTaintParam(t *testing.T) {
	// 1. Reflect on ScanPANInput and assert IncludeTaint exists with the right tag.
	rt := reflect.TypeOf(panscanner.ScanPANInput{})
	field, ok := rt.FieldByName("IncludeTaint")
	if !ok {
		t.Fatal("ScanPANInput must expose an IncludeTaint field")
	}
	if field.Type.Kind() != reflect.Bool {
		t.Fatalf("IncludeTaint must be bool, got %s", field.Type.Kind())
	}
	jsonTag := field.Tag.Get("json")
	if !strings.Contains(jsonTag, "include_taint") {
		t.Fatalf("IncludeTaint json tag must contain include_taint, got %q", jsonTag)
	}
	schemaTag := field.Tag.Get("jsonschema")
	if !strings.Contains(schemaTag, "go/packages") {
		t.Fatalf("IncludeTaint jsonschema tag must mention go/packages, got %q", schemaTag)
	}
	if !strings.Contains(schemaTag, "Default false") {
		t.Fatalf("IncludeTaint jsonschema tag must mention Default false, got %q", schemaTag)
	}

	// 2. Verify the tool handler accepts include_taint=false as a no-op (default
	// behavior, byte-identical to). We pass false here so we don't pay
	// the packages.Load cost on every test run.
	session := setupTestServer(t)
	tmpDir := t.TempDir()
	cleanFile := filepath.Join(tmpDir, "clean.go")
	content := `package test

type Order struct {
	ID     string
	Amount int
}
`
	if err := os.WriteFile(cleanFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "scan_pan_data",
		Arguments: map[string]any{
			"path":          tmpDir,
			"include_taint": false,
		},
	})
	if err != nil {
		t.Fatalf("CallTool with include_taint=false failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("Expected success, got IsError=true: %s", extractText(t, result))
	}
}
