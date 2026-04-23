package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testFileContent is 10 lines of known content for snippet tests.
const testFileContent = `line one
line two
line three
line four
line five
line six
line seven
line eight
line nine
line ten`

func createTestFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.go")
	if err := os.WriteFile(path, []byte(testFileContent), 0o644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	return path
}

func TestReadCodeSnippet(t *testing.T) {
	t.Parallel()
	path := createTestFile(t)

	tests := []struct {
		name       string
		filePath   string
		line       int
		wantNil    bool
		wantBefore string
		wantLine   string
		wantAfter  string
	}{
		{
			name:       "middle of file (line 5)",
			filePath:   path,
			line:       5,
			wantBefore: "line three\nline four",
			wantLine:   "line five",
			wantAfter:  "line six\nline seven",
		},
		{
			name:       "first line (no before)",
			filePath:   path,
			line:       1,
			wantBefore: "",
			wantLine:   "line one",
			wantAfter:  "line two\nline three",
		},
		{
			name:       "last line (no after)",
			filePath:   path,
			line:       10,
			wantBefore: "line eight\nline nine",
			wantLine:   "line ten",
			wantAfter:  "",
		},
		{
			name:       "line 2 (only 1 before line)",
			filePath:   path,
			line:       2,
			wantBefore: "line one",
			wantLine:   "line two",
			wantAfter:  "line three\nline four",
		},
		{
			name:     "nonexistent file",
			filePath: "/nonexistent/path/file.go",
			line:     1,
			wantNil:  true,
		},
		{
			name:     "line 0 (invalid)",
			filePath: path,
			line:     0,
			wantNil:  true,
		},
		{
			name:     "negative line",
			filePath: path,
			line:     -5,
			wantNil:  true,
		},
		{
			name:     "line beyond file length",
			filePath: path,
			line:     100,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snippet := ReadCodeSnippet(tt.filePath, tt.line)

			if tt.wantNil {
				if snippet != nil {
					t.Errorf("ReadCodeSnippet() = %+v, want nil", snippet)
				}
				return
			}

			if snippet == nil {
				t.Fatal("ReadCodeSnippet() = nil, want non-nil")
			}

			if snippet.Before != tt.wantBefore {
				t.Errorf("Before = %q, want %q", snippet.Before, tt.wantBefore)
			}
			if snippet.Line != tt.wantLine {
				t.Errorf("Line = %q, want %q", snippet.Line, tt.wantLine)
			}
			if snippet.After != tt.wantAfter {
				t.Errorf("After = %q, want %q", snippet.After, tt.wantAfter)
			}
		})
	}
}

func TestCodeSnippetJSON(t *testing.T) {
	t.Parallel()
	snippet := &CodeSnippet{
		Before: "line before",
		Line:   "flagged line",
		After:  "line after",
	}

	data, err := json.Marshal(snippet)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	for _, key := range []string{"before", "line", "after"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON missing key %q", key)
		}
	}
}

func TestFindingMetadata_Populated(t *testing.T) {
	t.Parallel()
	f := Finding{
		RuleID:        "TEST-001",
		Severity:      SeverityCritical,
		RequirementID: "3.3.1",
		FilePath:      "test.go",
		Line:          10,
		Description:   "test finding",
		Suggestion:    "fix it",
		Confidence:    "high",
		DevContext:    true,
		CodeSnippet: &CodeSnippet{
			Before: "before",
			Line:   "the line",
			After:  "after",
		},
		TriageHint:         "scanner flagged hardcoded key",
		FixHint:            "use key management service",
		MiddlewareDetected: true,
		SQLPatternMatched:  true,
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	jsonStr := string(data)

	// All new metadata fields should be present.
	expectedKeys := []string{
		`"confidence"`,
		`"dev_context"`,
		`"code_snippet"`,
		`"triage_hint"`,
		`"fix_hint"`,
		`"middleware_detected"`,
		`"sql_pattern_matched"`,
	}
	for _, key := range expectedKeys {
		if !strings.Contains(jsonStr, key) {
			t.Errorf("JSON missing key %s, got: %s", key, jsonStr)
		}
	}
}

func TestFindingMetadata_OmitEmpty(t *testing.T) {
	t.Parallel()
	f := Finding{
		RuleID:        "TEST-002",
		Severity:      SeverityHigh,
		RequirementID: "6.2.4",
		FilePath:      "test.go",
		Line:          5,
		Description:   "test",
		Suggestion:    "fix",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	jsonStr := string(data)

	// All new metadata fields should be ABSENT when zero-valued (omitempty).
	absentKeys := []string{
		`"confidence"`,
		`"dev_context"`,
		`"code_snippet"`,
		`"triage_hint"`,
		`"fix_hint"`,
		`"middleware_detected"`,
		`"sql_pattern_matched"`,
	}
	for _, key := range absentKeys {
		if strings.Contains(jsonStr, key) {
			t.Errorf("JSON should NOT contain %s when zero-valued, got: %s", key, jsonStr)
		}
	}
}
