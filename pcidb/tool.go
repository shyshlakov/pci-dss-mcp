package pcidb

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ExplainInput is the input type for the explain_requirement tool.
type ExplainInput struct {
	RequirementID string `json:"requirement_id" jsonschema:"PCI DSS v4.0.1 requirement ID (e.g. 3.3.1 or 8.3.6)"`
}

// ExplainRequirementOutput is the typed MCP output for explain_requirement.
// The SDK auto-infers OutputSchema from the struct tags here.
type ExplainRequirementOutput struct {
	Requirement *Requirement `json:"requirement" jsonschema:"PCI DSS v4.0.1 requirement record (title, description, testing procedure, detectability, accuracy metadata)"`
}

// RegisterTools registers all pcidb MCP tools on the given server.
func RegisterTools(server *mcp.Server, db *DB) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "explain_requirement",
		Description: "Look up a PCI DSS v4.0.1 requirement by ID. Returns title, description, and testing procedure.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ExplainInput) (*mcp.CallToolResult, *ExplainRequirementOutput, error) {
		id := strings.TrimSpace(input.RequirementID)

		r := db.Lookup(id)
		if r == nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{
						Text: fmt.Sprintf("Unknown requirement ID: %q. Use format like 3.3.1, 8.3.6, or 6.4.3.", id),
					},
				},
				IsError: true,
			}, nil, nil
		}

		out := &ExplainRequirementOutput{Requirement: r}
		summary := fmt.Sprintf("explain_requirement: PCI DSS v4.0.1 requirement %s - %s", r.RequirementID, r.Title)
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		}, out, nil
	})
}
