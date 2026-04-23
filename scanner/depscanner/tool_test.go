package depscanner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner/depscanner"
)

func setupToolServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "depscanner-test", Version: "v0.0.1"}, nil)
	depscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

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

func TestCheckDepsToolRegistered(t *testing.T) {
	session := setupToolServer(t)

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "check_dependencies" {
			found = true
			break
		}
	}
	if !found {
		t.Error("check_dependencies tool not found in ListTools response")
	}
}

func TestUpdateDBToolRegistered(t *testing.T) {
	session := setupToolServer(t)

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range tools.Tools {
		if tool.Name == "update_vulnerability_db" {
			found = true
			break
		}
	}
	if !found {
		t.Error("update_vulnerability_db tool not found in ListTools response")
	}
}

func TestCheckDepsInvalidMode(t *testing.T) {
	session := setupToolServer(t)

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

	text := extractToolText(t, result)
	if !strings.Contains(text, "Invalid mode") {
		t.Errorf("Expected 'Invalid mode' in error, got: %s", text)
	}
}

func TestCheckDepsDefaultMode(t *testing.T) {
	session := setupToolServer(t)

	// Call without mode — should default to "auto" and return an error
	// (no go.mod in temp dir), but the error should NOT be about invalid mode.
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": t.TempDir(),
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}

	// Should get an error about missing go.mod, not about invalid mode.
	if !result.IsError {
		t.Fatal("Expected IsError=true for missing go.mod")
	}

	text := extractToolText(t, result)
	if strings.Contains(text, "Invalid mode") {
		t.Errorf("Default mode should be 'auto', but got invalid mode error: %s", text)
	}
	// The error should mention go.mod or parse.
	if !strings.Contains(text, "go.mod") {
		t.Errorf("Expected error about go.mod, got: %s", text)
	}
}
