package scriptscanner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
)

// setupToolTestServer creates a server with check_payment_page_scripts
// registered, connects an in-memory client, and returns the client session.
func setupToolTestServer(t *testing.T) *mcp.ClientSession {
	t.Helper()

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-tool-test", Version: "v0.0.1"}, nil)
	scriptscanner.RegisterTools(server)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()

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

// TestToolRegistration verifies the check_payment_page_scripts tool is registered
// with the correct name and appears in the tool list.
func TestToolRegistration(t *testing.T) {
	t.Parallel()
	session := setupToolTestServer(t)

	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range result.Tools {
		if tool.Name == "check_payment_page_scripts" {
			found = true
			// Verify description mentions PCI DSS requirements.
			if !strings.Contains(tool.Description, "6.4.3") {
				t.Errorf("Expected description to mention 6.4.3, got: %s", tool.Description)
			}
			if !strings.Contains(tool.Description, "11.6.1") {
				t.Errorf("Expected description to mention 11.6.1, got: %s", tool.Description)
			}
			break
		}
	}

	if !found {
		t.Error("check_payment_page_scripts tool not found in ListTools result")
	}
}

// TestToolInputValidation verifies that calling the tool with an empty path
// returns an error response.
func TestToolInputValidation(t *testing.T) {
	t.Parallel()
	session := setupToolTestServer(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_payment_page_scripts",
		Arguments: map[string]any{
			"path": "",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for empty path")
	}

	// Verify error message contains tool name for diagnostics.
	if len(result.Content) > 0 {
		tc, ok := result.Content[0].(*mcp.TextContent)
		if ok && !strings.Contains(tc.Text, "check_payment_page_scripts") {
			t.Errorf("Expected error to mention tool name, got: %s", tc.Text)
		}
	}
}
