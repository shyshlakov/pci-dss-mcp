package main

import (
	"strings"
	"testing"
)

func TestServerInstructions_ContainsKeyGuidance(t *testing.T) {
	tt := []struct {
		name       string
		mustContain string
	}{
		{"recommended entry point name", "triage_findings"},
		{"audit entry point name", "generate_compliance_report"},
		{"requirement lookup tool name", "explain_requirement"},
		{"docker path recovery hint", "container mount"},
		{"taint performance hint", "taint engine"},
		{"pagination hint", "next_cursor"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(serverInstructions, tc.mustContain) {
				t.Fatalf("serverInstructions must mention %q so the LLM learns it on every turn", tc.mustContain)
			}
		})
	}
}

func TestServerInstructions_WithinWordBudget(t *testing.T) {
	const budget = 250
	words := strings.Fields(serverInstructions)
	if len(words) > budget {
		t.Fatalf("serverInstructions is %d words; MCP guidance is to stay under %d (read every LLM turn)", len(words), budget)
	}
}
