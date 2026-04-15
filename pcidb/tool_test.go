package pcidb

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// parseExplainOutput re-marshals result.StructuredContent into the typed
// ExplainRequirementOutput.: explain_requirement now returns typed
// output via the MCP SDK's structured-content channel.
func parseExplainOutput(t *testing.T, result *mcp.CallToolResult) *ExplainRequirementOutput {
	t.Helper()
	if result.StructuredContent == nil {
		t.Fatalf("StructuredContent is nil; summary text: %s", extractText(t, result))
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var out ExplainRequirementOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal StructuredContent: %v\nraw: %s", err, string(raw))
	}
	return &out
}

// setupTestClient creates a server with explain_requirement registered,
// connects an in-memory client, and returns the client session.
func setupTestClient(t *testing.T) *mcp.ClientSession {
	t.Helper()

	db, err := New()
	if err != nil {
		t.Fatalf("pcidb.New() failed: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: "pci-dss-mcp-test", Version: "v0.0.1"}, nil)
	RegisterTools(server, db)

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

func TestExplainRequirementValidID(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "3.3.1"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatal("Expected success, got IsError=true")
	}

	out := parseExplainOutput(t, result)
	if out.Requirement == nil {
		t.Fatal("StructuredContent missing requirement")
	}
	if out.Requirement.RequirementID != "3.3.1" {
		t.Errorf("RequirementID = %q, want 3.3.1", out.Requirement.RequirementID)
	}
	if out.Requirement.Title == "" {
		t.Error("Requirement.Title should be non-empty")
	}
	if out.Requirement.Description == "" {
		t.Error("Requirement.Description should be non-empty")
	}
}

func TestExplainRequirementTestingProcedure(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "3.3.1"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatal("Expected success, got IsError=true")
	}

	out := parseExplainOutput(t, result)
	if out.Requirement == nil || out.Requirement.TestingProcedure == "" {
		t.Error("Requirement.TestingProcedure should be non-empty for detectable requirement 3.3.1")
	}
}

func TestExplainRequirementNonDetectable(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "1.1.1"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatal("Expected success, got IsError=true")
	}

	out := parseExplainOutput(t, result)
	if out.Requirement == nil {
		t.Fatal("StructuredContent missing requirement")
	}
	if out.Requirement.RequirementID != "1.1.1" {
		t.Errorf("RequirementID = %q, want 1.1.1", out.Requirement.RequirementID)
	}
	if out.Requirement.Title == "" {
		t.Error("Requirement.Title should be non-empty")
	}
	if out.Requirement.Description == "" {
		t.Error("Requirement.Description should be non-empty")
	}
}

func TestExplainRequirementNonexistent(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "nonexistent"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if !result.IsError {
		t.Fatal("Expected IsError=true for nonexistent requirement")
	}

	text := extractText(t, result)
	if !strings.Contains(text, "nonexistent") {
		t.Error("Error message should mention the bad ID")
	}
	// Should suggest format examples
	if !strings.Contains(text, "3.3.1") || !strings.Contains(text, "8.3.6") {
		t.Error("Error message should include format examples like 3.3.1 or 8.3.6")
	}
}

func TestExplainRequirementWhitespaceTrimming(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "  3.3.1  "},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatal("Expected success after whitespace trimming, got IsError=true")
	}

	out := parseExplainOutput(t, result)
	if out.Requirement == nil || out.Requirement.RequirementID != "3.3.1" {
		t.Errorf("Expected requirement 3.3.1 after whitespace trimming, got %+v", out.Requirement)
	}
}

func TestExplainRequirementNewInV4(t *testing.T) {
	session := setupTestClient(t)

	// 3.4.2 is new_in_v4
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "explain_requirement",
		Arguments: map[string]any{"requirement_id": "3.4.2"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatal("Expected success, got IsError=true")
	}

	out := parseExplainOutput(t, result)
	if out.Requirement == nil || !out.Requirement.NewInV4 {
		t.Errorf("Requirement 3.4.2 should have NewInV4=true, got %+v", out.Requirement)
	}
}

func TestExplainRequirementToolRegistered(t *testing.T) {
	session := setupTestClient(t)

	result, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	found := false
	for _, tool := range result.Tools {
		if tool.Name == "explain_requirement" {
			found = true
			if tool.Description == "" {
				t.Error("explain_requirement tool should have a non-empty description")
			}
			break
		}
	}
	if !found {
		t.Error("explain_requirement tool should be registered in the server")
	}
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
