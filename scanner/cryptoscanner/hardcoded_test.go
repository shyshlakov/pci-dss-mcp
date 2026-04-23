package cryptoscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestSQLExclusion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Positive cases: SQL queries should be excluded.
		{"SELECT basic", "SELECT id, name FROM users WHERE active = true", true},
		{"INSERT INTO", "INSERT INTO payments (amount, card_id) VALUES ($1, $2)", true},
		{"UPDATE", "UPDATE accounts SET balance = balance - $1 WHERE id = $2", true},
		{"DELETE FROM", "DELETE FROM sessions WHERE expired_at < NOW()", true},
		{"CREATE TABLE", "CREATE TABLE cards (id UUID PRIMARY KEY)", true},
		{"DROP TABLE", "DROP TABLE IF EXISTS temp_tokens", true},
		{"ALTER TABLE", "ALTER TABLE payments ADD COLUMN status TEXT", true},
		{"WITH CTE", "WITH cte AS (SELECT * FROM orders)", true},
		{"leading whitespace", "  SELECT * FROM payments", true},
		{"case insensitive", "select * from payments", true},
		{"mixed case", "Select id From users", true},
		{"tab prefix", "\tSELECT 1", true},
		{"INSERT lowercase", "insert into users (name) values ('test')", true},
		{"DELETE lowercase", "delete from sessions where id = $1", true},

		// Negative cases: not SQL, should NOT be excluded.
		{"secret prefix", "sk_live_abc123secret456", false},
		{"hex string", "abcdef1234567890abcdef1234567890", false},
		{"random high entropy", "some random high entropy string", false},
		{"empty string", "", false},
		{"short string", "SELECT", false}, // no trailing space/content after keyword
		{"partial keyword", "SELECTED items from shelf", false},
		{"UPDATING status", "UPDATING the system now", false},
		{"INSERTION point", "INSERTION point for data", false},

		// Regression: large input must not hang or allocate unbounded.
		{"large input no match", strings.Repeat("a", 10000), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSQLQuery(tt.input)
			if got != tt.want {
				t.Errorf("isSQLQuery(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCheckAssignment_SQLQuery(t *testing.T) {
	t.Parallel()
	// Verify that a variable assignment with an SQL query value produces zero
	// findings, even though the string has moderate entropy and length >= 16.
	fset := token.NewFileSet()
	f := fset.AddFile("test.go", -1, 100)
	_ = f

	// Build a minimal AST: BasicLit with an SQL query.
	sqlValue := &ast.BasicLit{
		Kind:  token.STRING,
		Value: `"SELECT * FROM cards WHERE pan = $1"`,
	}

	finding := checkAssignment("query", sqlValue, fset, "test.go")
	if finding != nil {
		t.Errorf("checkAssignment with SQL query should return nil, got: %+v", finding)
	}

	// Also verify a non-SQL high-entropy string still triggers.
	// 15-05: use a genuinely random fixture -- an A.Z alphabet run would now
	// be filtered out by isCharacterSet.
	nonSQLValue := &ast.BasicLit{
		Kind:  token.STRING,
		Value: `"ghp_zX9vQm2tL8jKrB4nYpF6sW1eR7aC"`,
	}

	finding = checkAssignment("config", nonSQLValue, fset, "test.go")
	if finding == nil {
		t.Error("checkAssignment with high-entropy non-SQL string should return a finding")
	}
}

// TestIsCharacterSet verifies: detection of character-set /
// alphabet strings such as "ABC...XYZabc...xyz0123456789".
func TestIsCharacterSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "classic alphanum (62 unique, mixed case + digits)",
			input: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			want:  true,
		},
		{
			name:  "lowercase alphabet 26 chars",
			input: "abcdefghijklmnopqrstuvwxyz",
			want:  true,
		},
		{
			name:  "digits substring + prefix (len 21, contains 0123456789)",
			input: "0123456789ABCDEFGHIJK",
			want:  true,
		},
		{
			name:  "too short (len 10)",
			input: "0123456789",
			want:  false,
		},
		{
			name:  "too short (len 6)",
			input: "abcabc",
			want:  false,
		},
		{
			name:  "len 24 but only 1 unique byte",
			input: "aaaaaaaaaaaaaaaaaaaaaaaa",
			want:  false,
		},
		{
			name:  "real random secret 36 unique chars, no alphabet run",
			input: "zX9vQm2tL8jKrB4nYpF6sW1eR7aC3hGdJkMo",
			want:  false,
		},
		{
			name:  "len 26 but unique count below 70%",
			input: "password-for-testingabcdef",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isCharacterSet(tt.input)
			if got != tt.want {
				t.Errorf("isCharacterSet(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// parseAndScan is a test helper that parses inline Go source and runs
// checkHardcodedKeys over it.
func parseAndScan(t *testing.T, src string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parser.ParseFile: %v", err)
	}
	findings := checkHardcodedKeys(file, fset, "test.go")
	descriptions := make([]string, 0, len(findings))
	for _, f := range findings {
		descriptions = append(descriptions, f.RuleID+": "+f.Description)
	}
	return descriptions
}

// `alphanum` character-set constant must NOT fire CRYPTO-HARDCODED-KEY.
func TestCheckAssignment_AlphanumVarNotFlagged(t *testing.T) {
	t.Parallel()
	src := `package generator

var alphanum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
`
	findings := parseAndScan(t, src)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for alphanum character set, got %d: %v", len(findings), findings)
	}
}

// TestCheckAssignment_APIPathNotFlagged_Mastercard verifies: API
// endpoint path constants with multi-segment slash-separated values must NOT
// fire CRYPTO-HARDCODED-KEY on any tier.
func TestCheckAssignment_APIPathNotFlagged_Mastercard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "checkoutPath /src/api/digital/payments/transaction/credentials",
			src: `package mastercard

var checkoutPath = "/src/api/digital/payments/transaction/credentials"
`,
		},
		{
			name: "lookupAuthenticationPath /api/digital/authentication/lookup",
			src: `package mastercard

var lookupAuthenticationPath = "/api/digital/authentication/lookup"
`,
		},
		{
			name: "api path with dotted version segment",
			src: `package foo

var apiV1Path = "/api/v1.0/resources/list"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := parseAndScan(t, tt.src)
			if len(findings) != 0 {
				t.Errorf("expected 0 findings for API path, got %d: %v", len(findings), findings)
			}
		})
	}
}

// TestCheckAssignment_TrueSecretStillFlagged is a regression guard:
// real high-entropy random keys must still be flagged after the
// character-set and URL-path exclusions are added.
func TestCheckAssignment_TrueSecretStillFlagged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "random 36-char api key",
			src: `package foo

var apiKey = "zX9vQm2tL8jKrB4nYpF6sW1eR7aC3hGdJkMo"
`,
		},
		{
			name: "base64-shaped 48-char key",
			src: `package foo

var key = "dGhpc2lzYXRlc3RrZXl0aGF0aXNsb25nYW5kcmFuZG9tYWYK"
`,
		},
		{
			name: "24-char mixed alphanumeric token",
			src: `package foo

var apiToken = "abcdefghABCDEFGH12345678"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := parseAndScan(t, tt.src)
			if len(findings) == 0 {
				t.Errorf("expected at least one finding for real secret, got 0")
			}
		})
	}
}

// TestCheckAssignment_APIPathWithDisallowedCharsStillFlagged is a regression
// guard: a value that starts with /api/ but contains characters
// outside the URL-safe set (e.g., '=' or '+') must still be flagged.
func TestCheckAssignment_APIPathWithDisallowedCharsStillFlagged(t *testing.T) {
	t.Parallel()
	src := `package foo

var apiKey = "/api/x=base64padding+abcdefghij"
`
	findings := parseAndScan(t, src)
	if len(findings) == 0 {
		t.Errorf("expected at least one finding for /api/ value with disallowed chars, got 0")
	}
}
