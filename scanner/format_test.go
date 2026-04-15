package scanner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// extractText extracts the combined text from a CallToolResult's Content.
func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if result == nil {
		t.Fatal("FormatResult returned nil")
	}
	if len(result.Content) == 0 {
		t.Fatal("FormatResult returned empty Content")
	}
	var sb strings.Builder
	for _, c := range result.Content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			t.Fatalf("expected TextContent, got %T", c)
		}
		sb.WriteString(tc.Text)
	}
	return sb.String()
}

func TestFormatResultZeroFindings(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: nil,
		Metadata: ScanMetadata{
			ScannedFiles: 42,
			ScannedLines: 1500,
			DurationMS:   123,
		},
	}, "test_scanner")

	text := extractText(t, result)

	if !strings.Contains(text, "No violations found.") {
		t.Errorf("zero-findings output should contain 'No violations found.', got:\n%s", text)
	}
	if !strings.Contains(text, "42") {
		t.Errorf("zero-findings output should contain scanned_files count, got:\n%s", text)
	}
	if !strings.Contains(text, "1500") {
		t.Errorf("zero-findings output should contain scanned_lines count, got:\n%s", text)
	}
	if !strings.Contains(text, "123") {
		t.Errorf("zero-findings output should contain duration_ms, got:\n%s", text)
	}
}

func TestFormatResultOneCriticalFinding(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{
				RuleID:        "PAN-001",
				Severity:      SeverityCritical,
				RequirementID: "3.4.1",
				FilePath:      "payment/handler.go",
				Line:          42,
				Description:   "PAN displayed in plaintext",
				Suggestion:    "Mask PAN to show only first 6 and last 4 digits",
			},
		},
		Metadata: ScanMetadata{
			ScannedFiles: 10,
			ScannedLines: 500,
			DurationMS:   50,
		},
	}, "pan_scanner")

	text := extractText(t, result)

	if !strings.Contains(text, "1 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW, 0 INFO") {
		t.Errorf("summary should show '1 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings', got:\n%s", text)
	}
	if !strings.Contains(text, "[CRITICAL]") {
		t.Errorf("finding block should contain [CRITICAL], got:\n%s", text)
	}
	if !strings.Contains(text, "PAN displayed in plaintext") {
		t.Errorf("finding block should contain description, got:\n%s", text)
	}
	if !strings.Contains(text, "3.4.1") {
		t.Errorf("finding block should contain requirement_id, got:\n%s", text)
	}
	if !strings.Contains(text, "payment/handler.go:42") {
		t.Errorf("finding block should contain file:line, got:\n%s", text)
	}
	if !strings.Contains(text, "Mask PAN") {
		t.Errorf("finding block should contain suggestion, got:\n%s", text)
	}
	if !strings.Contains(text, "pci-ignore") {
		t.Errorf("finding block should contain pci-ignore hint, got:\n%s", text)
	}
}

func TestFormatResultMixedSeverities(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "PAN-001", Severity: SeverityCritical, RequirementID: "3.4.1", FilePath: "a.go", Line: 1, Description: "critical finding", Suggestion: "fix it"},
			{RuleID: "ENC-001", Severity: SeverityHigh, RequirementID: "4.2.1", FilePath: "b.go", Line: 2, Description: "high finding", Suggestion: "fix it"},
			{RuleID: "ENC-002", Severity: SeverityHigh, RequirementID: "4.2.1", FilePath: "c.go", Line: 3, Description: "another high finding", Suggestion: "fix it"},
			{RuleID: "AUTH-001", Severity: SeverityMedium, RequirementID: "8.3.7", FilePath: "d.go", Line: 4, Description: "medium finding", Suggestion: "fix it"},
		},
		Metadata: ScanMetadata{ScannedFiles: 4, ScannedLines: 200, DurationMS: 30},
	}, "mixed_scanner")

	text := extractText(t, result)

	if !strings.Contains(text, "1 CRITICAL, 2 HIGH, 1 MEDIUM, 0 LOW, 0 INFO") {
		t.Errorf("summary should show correct counts, got:\n%s", text)
	}
}

func TestFormatResultJSONSection(t *testing.T) {
	findings := []Finding{
		{
			RuleID:        "PAN-001",
			Severity:      SeverityCritical,
			RequirementID: "3.4.1",
			FilePath:      "payment/handler.go",
			Line:          42,
			Description:   "PAN displayed in plaintext",
			Suggestion:    "Mask PAN to show only first 6 and last 4 digits",
		},
	}
	result := FormatResult(&ScanResult{
		Findings: findings,
		Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 100, DurationMS: 10},
	}, "test_scanner")

	text := extractText(t, result)

	// Find JSON section after "JSON:" marker
	jsonIdx := strings.Index(text, "JSON:\n")
	if jsonIdx == -1 {
		t.Fatalf("output should contain 'JSON:' marker, got:\n%s", text)
	}
	jsonStr := text[jsonIdx+len("JSON:\n"):]

	// Verify it's valid JSON that can be unmarshaled to []Finding
	var parsed []Finding
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("JSON section is not valid JSON: %v\nJSON:\n%s", err, jsonStr)
	}
	if len(parsed) != 1 {
		t.Errorf("JSON should contain 1 finding, got %d", len(parsed))
	}
	if parsed[0].RuleID != "PAN-001" {
		t.Errorf("parsed finding RuleID = %q, want %q", parsed[0].RuleID, "PAN-001")
	}
}

func TestFormatResultNoEmojis(t *testing.T) {
	// Test with findings
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "PAN-001", Severity: SeverityCritical, RequirementID: "3.4.1", FilePath: "a.go", Line: 1, Description: "test", Suggestion: "fix"},
		},
		Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 100, DurationMS: 10},
	}, "test")
	text := extractText(t, result)
	assertNoEmojis(t, text, "findings output")

	// Test zero findings
	result2 := FormatResult(&ScanResult{
		Findings: nil,
		Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 100, DurationMS: 10},
	}, "test")
	text2 := extractText(t, result2)
	assertNoEmojis(t, text2, "zero-findings output")
}

func assertNoEmojis(t *testing.T, text string, context string) {
	t.Helper()
	for _, r := range text {
		if r > 0x1F600 && r < 0x1F9FF {
			t.Errorf("%s contains emoji character U+%04X", context, r)
			return
		}
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}
	for _, tt := range tests {
		if string(tt.sev) != tt.want {
			t.Errorf("Severity constant = %q, want %q", tt.sev, tt.want)
		}
	}
}

func TestFormatResultInfoSeverity(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "PAN-010", Severity: SeverityInfo, RequirementID: "3.4.1", FilePath: "test_helper.go", Line: 5, Description: "test variable with PAN keyword", Suggestion: "informational only"},
		},
		Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 50, DurationMS: 5},
	}, "pan_scanner")

	text := extractText(t, result)

	if !strings.Contains(text, "0 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW, 1 INFO findings") {
		t.Errorf("summary should include INFO count, got:\n%s", text)
	}
}

func TestFormatResultMixedWithInfo(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "PAN-001", Severity: SeverityCritical, RequirementID: "3.4.1", FilePath: "a.go", Line: 1, Description: "critical", Suggestion: "fix"},
			{RuleID: "PAN-010", Severity: SeverityInfo, RequirementID: "3.4.1", FilePath: "b.go", Line: 2, Description: "info", Suggestion: "note"},
			{RuleID: "PAN-011", Severity: SeverityInfo, RequirementID: "3.4.1", FilePath: "c.go", Line: 3, Description: "info2", Suggestion: "note"},
		},
		Metadata: ScanMetadata{ScannedFiles: 3, ScannedLines: 150, DurationMS: 10},
	}, "pan_scanner")

	text := extractText(t, result)

	if !strings.Contains(text, "1 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW, 2 INFO findings") {
		t.Errorf("summary should show correct counts including INFO, got:\n%s", text)
	}
}

func TestFormatResultFindingBlockSeparators(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "A-001", Severity: SeverityCritical, RequirementID: "3.4.1", FilePath: "a.go", Line: 1, Description: "first", Suggestion: "fix1"},
			{RuleID: "A-002", Severity: SeverityHigh, RequirementID: "4.2.1", FilePath: "b.go", Line: 2, Description: "second", Suggestion: "fix2"},
		},
		Metadata: ScanMetadata{ScannedFiles: 2, ScannedLines: 200, DurationMS: 20},
	}, "test")

	text := extractText(t, result)

	// Findings should be separated by "---"
	if !strings.Contains(text, "---") {
		t.Errorf("findings should be separated by '---', got:\n%s", text)
	}
}

func TestFormatResultIsTextContent(t *testing.T) {
	result := FormatResult(&ScanResult{
		Findings: []Finding{
			{RuleID: "A-001", Severity: SeverityCritical, RequirementID: "3.4.1", FilePath: "a.go", Line: 1, Description: "test", Suggestion: "fix"},
		},
		Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 100, DurationMS: 10},
	}, "test")

	if result == nil {
		t.Fatal("FormatResult returned nil")
	}
	for i, c := range result.Content {
		if _, ok := c.(*mcp.TextContent); !ok {
			t.Errorf("Content[%d] is %T, want *mcp.TextContent", i, c)
		}
	}
}
