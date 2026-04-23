package secretscanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStripJSONComments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "line comment removed",
			input:    "{\"key\": \"val\" // comment\n}",
			expected: "{\"key\": \"val\" \n}",
		},
		{
			name:     "block comment removed",
			input:    `{"key": /* comment */ "val"}`,
			expected: `{"key":  "val"}`,
		},
		{
			name:     "preserves // inside string value",
			input:    `{"url": "https://example.com"}`,
			expected: `{"url": "https://example.com"}`,
		},
		{
			name:     "preserves /* inside string value",
			input:    `{"path": "a/* b */c"}`,
			expected: `{"path": "a/* b */c"}`,
		},
		{
			name:     "escaped quotes inside strings",
			input:    `{"key": "val\"ue // not comment"}`,
			expected: `{"key": "val\"ue // not comment"}`,
		},
		{
			name: "trailing comma in object",
			input: `{
  "a": 1,
  "b": 2,
}`,
			expected: `{
  "a": 1,
  "b": 2
}`,
		},
		{
			name:  "trailing comma in array",
			input: `[1, 2,]`,
			// trailing comma stripped
			expected: `[1, 2]`,
		},
		{
			name:  "multi-line block comment spanning 3+ lines",
			input: "{\n  \"key\": \"val\",\n  /*\n   * This is a big\n   * multi-line comment\n   */\n  \"other\": \"data\"\n}",
			// Block comment newlines are preserved for line structure.
			expected: "{\n  \"key\": \"val\",\n  \n\n\n\n  \"other\": \"data\"\n}",
		},
		{
			name:     "no comments -- pass through unchanged",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "empty input",
			input:    ``,
			expected: ``,
		},
		{
			name:     "line comment at end of line",
			input:    "{\"a\": 1 // trailing\n}",
			expected: "{\"a\": 1 \n}",
		},
		{
			name: "trailing comma after last object in array",
			input: `[
  {"id": 1},
  {"id": 2},
]`,
			expected: `[
  {"id": 1},
  {"id": 2}
]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripJSONComments([]byte(tt.input)))
			if got != tt.expected {
				t.Errorf("StripJSONComments(%q)\n  got:  %q\n  want: %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestStripJSONCommentsValidJSON verifies that stripped output is valid JSON.
func TestStripJSONCommentsValidJSON(t *testing.T) {
	t.Parallel()
	inputs := []string{
		`{"key": "val" // comment
		}`,
		`{"key": /* block */ "val"}`,
		`{"a": 1, "b": 2,}`,
		`[1, 2, 3,]`,
		`{
			// line comment
			"url": "https://example.com",
			"nested": {
				"arr": [1, 2, /* inline */ 3,],
			},
		}`,
	}

	for i, input := range inputs {
		stripped := StripJSONComments([]byte(input))
		var v any
		if err := json.Unmarshal(stripped, &v); err != nil {
			t.Errorf("input %d: stripped output is not valid JSON: %v\nstripped: %q", i, err, string(stripped))
		}
	}
}

// TestParseJSONFileJSONC verifies the full integration: ParseJSONFile succeeds
// on a.jsonc file with comments.
func TestParseJSONFileJSONC(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	content := `{
  // Database configuration
  "database": {
    "host": "db.example.com",
    "password": "s3cret!", /* TODO: use env var */
    "port": 5432,
  },
  "api": {
    "token": "ghp_test1234567890",
  },
}`
	path := filepath.Join(dir, "config.jsonc")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	kvs, err := ParseJSONFile(path)
	if err != nil {
		t.Fatalf("ParseJSONFile on JSONC content should succeed, got error: %v", err)
	}

	found := make(map[string]string)
	for _, kv := range kvs {
		found[kv.Key] = kv.Value
	}

	if v, ok := found["database.host"]; !ok || v != "db.example.com" {
		t.Errorf("database.host = %q, want %q", v, "db.example.com")
	}
	if v, ok := found["database.password"]; !ok || v != "s3cret!" {
		t.Errorf("database.password = %q, want %q", v, "s3cret!")
	}
	if v, ok := found["api.token"]; !ok || v != "ghp_test1234567890" {
		t.Errorf("api.token = %q, want %q", v, "ghp_test1234567890")
	}
}
