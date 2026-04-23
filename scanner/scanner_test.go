package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinding_RelatedRequirements_JSON(t *testing.T) {
	t.Parallel()
	t.Run("marshals related_requirements when populated", func(t *testing.T) {
		f := Finding{
			RuleID:              "CRYPTO-HARDCODED-KEY",
			Severity:            SeverityCritical,
			RequirementID:       "6.2.4",
			FilePath:            "main.go",
			Line:                10,
			Description:         "Hardcoded encryption key",
			Suggestion:          "Use env var",
			RelatedRequirements: []string{"3.6.1.2"},
		}
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		s := string(data)
		if !strings.Contains(s, `"related_requirements":["3.6.1.2"]`) {
			t.Errorf("expected related_requirements in JSON, got: %s", s)
		}
	})

	t.Run("omits related_requirements when nil", func(t *testing.T) {
		f := Finding{
			RuleID:        "CRYPTO-HARDCODED-KEY",
			Severity:      SeverityCritical,
			RequirementID: "6.2.4",
			FilePath:      "main.go",
			Line:          10,
			Description:   "Hardcoded encryption key",
			Suggestion:    "Use env var",
		}
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		s := string(data)
		if strings.Contains(s, "related_requirements") {
			t.Errorf("expected no related_requirements in JSON, got: %s", s)
		}
	})

	t.Run("omits related_requirements when empty slice", func(t *testing.T) {
		f := Finding{
			RuleID:              "TEST",
			Severity:            SeverityMedium,
			RequirementID:       "1.1.1",
			FilePath:            "test.go",
			Line:                1,
			Description:         "Test",
			Suggestion:          "Test",
			RelatedRequirements: []string{},
		}
		data, err := json.Marshal(f)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		s := string(data)
		if strings.Contains(s, "related_requirements") {
			t.Errorf("expected no related_requirements in JSON for empty slice, got: %s", s)
		}
	})
}

func TestFormatResult_AlsoSatisfies(t *testing.T) {
	t.Parallel()
	t.Run("shows Also satisfies for single related requirement", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					RuleID:              "CRYPTO-HARDCODED-KEY",
					Severity:            SeverityCritical,
					RequirementID:       "6.2.4",
					FilePath:            "main.go",
					Line:                10,
					Description:         "Hardcoded encryption key",
					Suggestion:          "Use env var",
					RelatedRequirements: []string{"3.6.1.2"},
				},
			},
			Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 100, DurationMS: 5},
		}
		callResult := FormatResult(result, "encryption")
		text := extractText(t, callResult)
		if !strings.Contains(text, "Also satisfies: 3.6.1.2") {
			t.Errorf("expected 'Also satisfies: 3.6.1.2' in output, got:\n%s", text)
		}
	})

	t.Run("shows Also satisfies for multiple related requirements", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					RuleID:              "TLS-INSECURE-SKIP-VERIFY",
					Severity:            SeverityCritical,
					RequirementID:       "4.2.1",
					FilePath:            "client.go",
					Line:                20,
					Description:         "InsecureSkipVerify is true",
					Suggestion:          "Remove InsecureSkipVerify",
					RelatedRequirements: []string{"4.2.1.1", "2.2.7"},
				},
			},
			Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 50, DurationMS: 3},
		}
		callResult := FormatResult(result, "tls")
		text := extractText(t, callResult)
		if !strings.Contains(text, "Also satisfies: 4.2.1.1, 2.2.7") {
			t.Errorf("expected 'Also satisfies: 4.2.1.1, 2.2.7' in output, got:\n%s", text)
		}
	})

	t.Run("does not show Also satisfies when no related requirements", func(t *testing.T) {
		result := &ScanResult{
			Findings: []Finding{
				{
					RuleID:        "TEST-RULE",
					Severity:      SeverityMedium,
					RequirementID: "1.1.1",
					FilePath:      "test.go",
					Line:          5,
					Description:   "Test finding",
					Suggestion:    "Fix it",
				},
			},
			Metadata: ScanMetadata{ScannedFiles: 1, ScannedLines: 10, DurationMS: 1},
		}
		callResult := FormatResult(result, "test")
		text := extractText(t, callResult)
		if strings.Contains(text, "Also satisfies") {
			t.Errorf("expected no 'Also satisfies' in output, got:\n%s", text)
		}
	})
}
