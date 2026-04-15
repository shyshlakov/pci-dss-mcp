package reportscanner

import (
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestFilterFindings(t *testing.T) {
	sample := []scanner.Finding{
		{RuleID: "PAN-KEYWORD", Severity: scanner.SeverityHigh},
		{RuleID: "PAN-TYPE", Severity: scanner.SeverityHigh},
		{RuleID: "AUTH-MISSING-MFA", Severity: scanner.SeverityHigh},
		{RuleID: "AUDIT-NO-LOG", Severity: scanner.SeverityMedium},
		{RuleID: "INFO-SOMETHING", Severity: scanner.SeverityInfo},
	}

	tests := []struct {
		name    string
		minSev  string
		ruleF   string
		limit   int
		wantN   int
		wantErr bool
	}{
		{"no filter", "", "", 0, 5, false},
		{"min high drops medium and info", "HIGH", "", 0, 3, false},
		{"min critical drops everything", "CRITICAL", "", 0, 0, false},
		{"min medium keeps high+medium", "MEDIUM", "", 0, 4, false},
		{"exact comma list", "", "PAN-KEYWORD,PAN-TYPE", 0, 2, false},
		{"exact single rule", "", "AUTH-MISSING-MFA", 0, 1, false},
		{"regex PAN", "", "/PAN-.*/", 0, 2, false},
		{"regex AUDIT", "", "/AUDIT-.*/", 0, 1, false},
		{"bad regex", "", "/[invalid/", 0, 0, true},
		{"limit 2", "", "", 2, 2, false},
		{"limit larger than slice", "", "", 99, 5, false},
		{"combined hi + auth regex + limit 5", "HIGH", "/AUTH-.*/", 5, 1, false},
		{"combined medium + regex + limit", "MEDIUM", "/PAN-.*/", 1, 1, false},
		{"unknown severity name treated as no filter", "BOGUS", "", 0, 5, false},
		{"case-insensitive severity", "high", "", 0, 3, false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := FilterFindings(sample, tt.minSev, tt.ruleF, tt.limit)
			if (err != nil) != tt.wantErr {
				t.Fatalf("FilterFindings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != tt.wantN {
				t.Fatalf("FilterFindings() returned %d findings, want %d. result=%v", len(got), tt.wantN, got)
			}
		})
	}
}

func TestFilterFindings_DoesNotMutateInput(t *testing.T) {
	input := []scanner.Finding{
		{RuleID: "A", Severity: scanner.SeverityHigh},
		{RuleID: "B", Severity: scanner.SeverityMedium},
	}
	originalLen := len(input)

	_, err := FilterFindings(input, "HIGH", "", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(input) != originalLen {
		t.Errorf("input slice length changed from %d to %d", originalLen, len(input))
	}
	if input[0].RuleID != "A" || input[1].RuleID != "B" {
		t.Errorf("input slice content mutated: %v", input)
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		sev  scanner.Severity
		want int
	}{
		{scanner.SeverityCritical, 5},
		{scanner.SeverityHigh, 4},
		{scanner.SeverityMedium, 3},
		{scanner.SeverityLow, 2},
		{scanner.SeverityInfo, 1},
		{scanner.Severity(""), 0},
		{scanner.Severity("UNKNOWN"), 0},
	}
	for _, tt := range tests {
		if got := severityRank(tt.sev); got != tt.want {
			t.Errorf("severityRank(%q) = %d, want %d", tt.sev, got, tt.want)
		}
	}
}

func TestSeverityFromString(t *testing.T) {
	tests := []struct {
		input  string
		want   scanner.Severity
		wantOK bool
	}{
		{"CRITICAL", scanner.SeverityCritical, true},
		{"HIGH", scanner.SeverityHigh, true},
		{"high", scanner.SeverityHigh, true},
		{"  High  ", scanner.SeverityHigh, true},
		{"MEDIUM", scanner.SeverityMedium, true},
		{"LOW", scanner.SeverityLow, true},
		{"INFO", scanner.SeverityInfo, true},
		{"", "", false},
		{"bogus", "", false},
	}
	for _, tt := range tests {
		got, ok := severityFromString(tt.input)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("severityFromString(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.wantOK)
		}
	}
}
