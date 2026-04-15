package triagescanner

import (
	"context"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// TestTriageSkipsVerifiedOK asserts that verified-OK marker findings
// (AUDIT-LOG-OK, CSP-OK) are dropped from TriageResult.Findings before
// context enrichment. The generate_compliance_report output is unchanged
// verified-OK markers remain visible to QSA auditors per the project conventions
// "INFO for verified-OK" convention. closure.
func TestTriageSkipsVerifiedOK(t *testing.T) {
	tt := []struct {
		name    string
		ruleID  string
		skipped bool
	}{
		{"AUDIT-LOG-OK skipped", "AUDIT-LOG-OK", true},
		{"CSP-OK skipped", "CSP-OK", true},
		{"AUDIT-NO-LOG kept (violation)", "AUDIT-NO-LOG", false},
		{"PAN-KEYWORD kept (informational)", "PAN-KEYWORD", false},
		{"AUTH-MISSING-MFA kept", "AUTH-MISSING-MFA", false},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			findings := []scanner.Finding{
				{
					RuleID:        tc.ruleID,
					Severity:      scanner.SeverityInfo,
					RequirementID: "10.2.1",
					FilePath:      "internal/http/handler/payments.go",
					Line:          42,
					Description:   "test finding",
				},
			}

			engine := NewTriageEngine()
			result, err := engine.Triage(context.Background(), t.TempDir(), findings)
			if err != nil {
				t.Fatalf("Triage: %v", err)
			}

			got := len(result.Findings)
			want := 1
			if tc.skipped {
				want = 0
			}
			if got != want {
				t.Errorf("len(result.Findings) = %d, want %d (rule %s)", got, want, tc.ruleID)
			}

			if result.Metadata.FindingsTotal != 1 {
				t.Errorf("Metadata.FindingsTotal = %d, want 1 (original input count must be preserved even when skipping)", result.Metadata.FindingsTotal)
			}
		})
	}
}

func TestIsVerifiedOKRule(t *testing.T) {
	tt := []struct {
		ruleID string
		want   bool
	}{
		{"AUDIT-LOG-OK", true},
		{"CSP-OK", true},
		{"TLS-OK", true}, // hypothetical future rule
		{"AUDIT-NO-LOG", false},
		{"PAN-KEYWORD", false},
		{"AUTH-MISSING-MFA", false},
		{"", false},
		{"-OK", true}, // edge case — any suffix match counts
	}

	for _, tc := range tt {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := isVerifiedOKRule(tc.ruleID)
			if got != tc.want {
				t.Errorf("isVerifiedOKRule(%q) = %v, want %v", tc.ruleID, got, tc.want)
			}
		})
	}
}
