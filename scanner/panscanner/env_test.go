package panscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// writeEnvTemp writes a.env file to a temp directory and returns the file path.
func writeEnvTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanEnvFile(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		wantFindings  int
		checkSeverity scanner.Severity
		checkRuleID   string
		checkDesc     string // substring match
	}{
		{
			name:          "PAN with keyword key",
			content:       "CARD_NUMBER=4111111111111111\n",
			wantFindings:  2, // PAN finding + sensitive key finding
			checkSeverity: scanner.SeverityCritical,
			checkRuleID:   "PAN-LITERAL",
			checkDesc:     "sensitive key name",
		},
		{
			name:          "PAN with non-keyword key",
			content:       "TEST_VALUE=4111111111111111\n",
			wantFindings:  1,
			checkSeverity: scanner.SeverityCritical,
			checkRuleID:   "PAN-LITERAL",
			checkDesc:     "card number detected",
		},
		{
			name:          "formatted PAN with dashes",
			content:       "SOME_KEY=4111-1111-1111-1111\n",
			wantFindings:  1,
			checkSeverity: scanner.SeverityCritical,
			checkRuleID:   "PAN-LITERAL",
			checkDesc:     "card number",
		},
		{
			name:         "non-PAN value",
			content:      "API_KEY=sk_test_abc123\n",
			wantFindings: 0,
		},
		{
			name:         "short numeric value",
			content:      "PORT=8080\n",
			wantFindings: 0,
		},
		{
			name:         "comment line skipped",
			content:      "# CARD_NUMBER=4111111111111111\n",
			wantFindings: 0,
		},
		{
			name:         "empty lines skipped",
			content:      "\n\n\n",
			wantFindings: 0,
		},
		{
			name:          "quoted value double quotes",
			content:       "DATA=\"4111111111111111\"\n",
			wantFindings:  1,
			checkSeverity: scanner.SeverityCritical,
			checkRuleID:   "PAN-LITERAL",
		},
		{
			name:          "quoted value single quotes",
			content:       "DATA='4111111111111111'\n",
			wantFindings:  1,
			checkSeverity: scanner.SeverityCritical,
			checkRuleID:   "PAN-LITERAL",
		},
		{
			name:          "sensitive key with non-PAN value",
			content:       "CARD_NUMBER=tokenized_ref_abc123\n",
			wantFindings:  1, // sensitive key finding only
			checkSeverity: scanner.SeverityHigh,
			checkRuleID:   "PAN-KEYWORD",
			checkDesc:     "sensitive data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeEnvTemp(t, tt.content)
			findings, _, err := scanEnvFile(path)
			if err != nil {
				t.Fatal(err)
			}

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d; findings: %+v", len(findings), tt.wantFindings, findings)
				return
			}

			if tt.wantFindings > 0 && tt.checkRuleID != "" {
				var matched bool
				for _, f := range findings {
					if f.RuleID == tt.checkRuleID && f.Severity == tt.checkSeverity {
						if tt.checkDesc == "" || strings.Contains(strings.ToLower(f.Description), strings.ToLower(tt.checkDesc)) {
							matched = true
							break
						}
					}
				}
				if !matched {
					t.Errorf("no finding matched RuleID=%s Severity=%s Desc contains %q; got: %+v",
						tt.checkRuleID, tt.checkSeverity, tt.checkDesc, findings)
				}
			}
		})
	}
}

func TestScanEnvFileLineNumbers(t *testing.T) {
	content := `# Database config
DB_HOST=localhost
DB_PORT=5432

# Payment data (should be flagged)
CARD_NUMBER=4111111111111111
`
	path := writeEnvTemp(t, content)
	findings, lineCount, err := scanEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if lineCount != 6 {
		t.Errorf("lineCount = %d, want 6", lineCount)
	}

	// CARD_NUMBER finding should be on line 6.
	var foundLine6 bool
	for _, f := range findings {
		if f.RuleID == "PAN-LITERAL" && f.Line == 6 {
			foundLine6 = true
			break
		}
	}
	if !foundLine6 {
		t.Errorf("expected PAN-LITERAL finding on line 6, got findings: %+v", findings)
	}
}

func TestScanEnvFileErrorHandling(t *testing.T) {
	// Non-existent file should return error.
	_, _, err := scanEnvFile("/nonexistent/.env")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestScanEnvFileRequirementID(t *testing.T) {
	content := "CARD_NUMBER=4111111111111111\n"
	path := writeEnvTemp(t, content)
	findings, _, err := scanEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PAN-LITERAL" && f.RequirementID != "3.4.1" {
			t.Errorf("PAN-LITERAL finding has RequirementID=%q, want %q", f.RequirementID, "3.4.1")
		}
	}
}

func TestScanEnvFileSuggestion(t *testing.T) {
	content := "DATA=4111111111111111\n"
	path := writeEnvTemp(t, content)
	findings, _, err := scanEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "PAN-LITERAL" && f.Suggestion == "" {
			t.Error("PAN-LITERAL finding should have a non-empty Suggestion")
		}
	}
}
