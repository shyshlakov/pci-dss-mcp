package authscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// parseSource is a test helper that parses inline Go source into AST.
// per-PackageInfo score cache means each subtest's
// pkgInfo carries its own isolated cache; no global reset is needed.
func parseSource(t *testing.T, src string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return file, fset
}

// expectedFinding describes what we expect in a finding.
type expectedFinding struct {
	ruleID   string
	severity scanner.Severity
	line     int
}

func TestAuthScannerInterface(t *testing.T) {
	s := New()
	var _ scanner.Scanner = s // compile-time interface check

	if got := s.Name(); got != "auth_strength" {
		t.Errorf("Name() = %q, want %q", got, "auth_strength")
	}
	if got := s.Requirements(); len(got) != 3 {
		t.Errorf("Requirements() = %v, want 3 items", got)
	}
}

func TestDetectHardcodedPasswords(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []expectedFinding
	}{
		{
			name: "var password with string literal",
			source: `package test
var password = "secret123"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 2},
			},
		},
		{
			name: "const dbpass with string literal",
			source: `package test
const dbpass = "admin"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 2},
			},
		},
		{
			name: "short assign password",
			source: `package test
func f() {
	password := "mypass"
	_ = password
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 3},
			},
		},
		{
			name: "placeholder changeme is INFO (dev-context does not upgrade)",
			source: `package test
var password = "changeme"
`,
			expected: []expectedFinding{
				// Authscanner classifies "changeme" as placeholder -> INFO.
				// Dev-context also sees "changeme" as placeholder -> MEDIUM candidate.
				// But MEDIUM > INFO, so dev-context does NOT upgrade. Stays INFO.
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityInfo, line: 2},
			},
		},
		{
			name: "placeholder env template is INFO",
			source: `package test
var password = "${DB_PASSWORD}"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityInfo, line: 2},
			},
		},
		{
			name: "empty string is INFO",
			source: `package test
var password = ""
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityInfo, line: 2},
			},
		},
		{
			name: "angle bracket placeholder is INFO",
			source: `package test
var password = "<replace-me>"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityInfo, line: 2},
			},
		},
		{
			name: "all-x placeholder is INFO",
			source: `package test
var password = "xxxx"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityInfo, line: 2},
			},
		},
		{
			name: "os.Setenv DB_PASSWORD with placeholder value is MEDIUM (dev-context)",
			source: `package test
import "os"
func f() {
	os.Setenv("DB_PASSWORD", "secret")
}
`,
			expected: []expectedFinding{
				// "secret" is a placeholder value per dev-context.
				// Non-dev, non-prod path -> placeholder-only downgrade to MEDIUM.
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "os.Setenv API_KEY is CRITICAL",
			source: `package test
import "os"
func f() {
	os.Setenv("API_KEY", "sk-live-abc")
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 4},
			},
		},
		{
			name: "os.Setenv AUTH_TOKEN is CRITICAL",
			source: `package test
import "os"
func f() {
	os.Setenv("AUTH_TOKEN", "bearer-xyz")
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 4},
			},
		},
		{
			name: "os.Setenv APP_SECRET is CRITICAL",
			source: `package test
import "os"
func f() {
	os.Setenv("APP_SECRET", "mysecret")
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 4},
			},
		},
		{
			name: "os.Setenv APP_NAME is not a secret key",
			source: `package test
import "os"
func f() {
	os.Setenv("APP_NAME", "myapp")
}
`,
			expected: nil,
		},
		{
			name: "username is not a password keyword",
			source: `package test
var username = "admin"
`,
			expected: nil,
		},
		{
			name: "passwordLength integer is not flagged",
			source: `package test
var passwordLength = 12
`,
			expected: nil,
		},
		{
			name: "passphrase keyword",
			source: `package test
var passphrase = "my-secret-phrase"
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-HARDCODED-PWD", severity: scanner.SeverityCritical, line: 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, fset := parseSource(t, tt.source)
			findings := detectHardcodedPasswords(file, fset, "test.go")
			assertFindings(t, findings, tt.expected)
		})
	}
}

func TestDetectWeakPasswordPolicy(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []expectedFinding
	}{
		{
			name: "len(password) < 8 is CRITICAL plus MEDIUM byte-count",
			source: `package test
func f() {
	password := "test"
	if len(password) < 8 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
				{ruleID: "AUTH-BYTE-COUNT", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "len(passwd) < 11 is CRITICAL plus MEDIUM",
			source: `package test
func f() {
	passwd := "test"
	if len(passwd) < 11 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
				{ruleID: "AUTH-BYTE-COUNT", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "len(password) < 12 is no finding",
			source: `package test
func f() {
	password := "test"
	if len(password) < 12 {
		panic("too short")
	}
}
`,
			expected: nil,
		},
		{
			name: "len(password) >= 12 is no finding",
			source: `package test
func f() {
	password := "test"
	if len(password) >= 12 {
		return
	}
}
`,
			expected: nil,
		},
		{
			name: "reversed comparison 8 > len(password) is CRITICAL",
			source: `package test
func f() {
	password := "test"
	if 8 > len(password) {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
				{ruleID: "AUTH-BYTE-COUNT", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "len(password) <= 7 is CRITICAL",
			source: `package test
func f() {
	password := "test"
	if len(password) <= 7 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
				{ruleID: "AUTH-BYTE-COUNT", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "utf8.RuneCountInString(password) < 8 is CRITICAL but no byte-count",
			source: `package test
import "unicode/utf8"
func f() {
	password := "test"
	if utf8.RuneCountInString(password) < 8 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 5},
			},
		},
		{
			name: "len([]rune(password)) < 8 is CRITICAL but no byte-count",
			source: `package test
func f() {
	password := "test"
	if len([]rune(password)) < 8 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
			},
		},
		{
			name: "len(password) <= 11 min accepted is 12 so not weak",
			source: `package test
func f() {
	password := "test"
	if len(password) <= 11 {
		panic("too short")
	}
}
`,
			expected: nil, // min accepted = 12, meets PCI DSS requirement
		},
		{
			name: "len(password) <= 10 min accepted is 11 so CRITICAL",
			source: `package test
func f() {
	password := "test"
	if len(password) <= 10 {
		panic("too short")
	}
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-WEAK-POLICY", severity: scanner.SeverityCritical, line: 4},
				{ruleID: "AUTH-BYTE-COUNT", severity: scanner.SeverityMedium, line: 4},
			},
		},
		{
			name: "len(username) < 8 is not a password variable",
			source: `package test
func f() {
	username := "test"
	if len(username) < 8 {
		panic("too short")
	}
}
`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, fset := parseSource(t, tt.source)
			findings := detectWeakPasswordPolicy(file, fset, "test.go")
			assertFindings(t, findings, tt.expected)
		})
	}
}

func TestDetectMissingMFA(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected []expectedFinding
	}{
		{
			name: "payment route with no MFA wrapper is HIGH",
			source: `package test
import "net/http"
func init() {
	http.HandleFunc("/payment/process", handlePayment)
}
func handlePayment(w http.ResponseWriter, r *http.Request) {}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-MISSING-MFA", severity: scanner.SeverityHigh, line: 4},
			},
		},
		{
			name: "payment route with mfaMiddleware wrapper is clean",
			source: `package test
import "net/http"
func init() {
	http.HandleFunc("/payment/process", mfaMiddleware(handlePayment))
}
func handlePayment(w http.ResponseWriter, r *http.Request) {}
func mfaMiddleware(h http.HandlerFunc) http.HandlerFunc { return h }
`,
			expected: nil,
		},
		{
			name: "payment route with totpRequired wrapper is clean",
			source: `package test
import "net/http"
func init() {
	http.HandleFunc("/payment/process", totpRequired(handlePayment))
}
func handlePayment(w http.ResponseWriter, r *http.Request) {}
func totpRequired(h http.HandlerFunc) http.HandlerFunc { return h }
`,
			expected: nil,
		},
		{
			name: "non-payment route is clean",
			source: `package test
import "net/http"
func init() {
	http.HandleFunc("/api/users", handleUsers)
}
func handleUsers(w http.ResponseWriter, r *http.Request) {}
`,
			expected: nil,
		},
		{
			name: "mux.HandleFunc checkout route without MFA is HIGH",
			source: `package test
import "net/http"
func init() {
	mux := http.NewServeMux()
	mux.HandleFunc("/checkout", handleCheckout)
}
func handleCheckout(w http.ResponseWriter, r *http.Request) {}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-MISSING-MFA", severity: scanner.SeverityHigh, line: 5},
			},
		},
		{
			name: "router.GET refund route without MFA is HIGH",
			source: `package test
func init() {
	router.GET("/api/refund", handleRefund)
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-MISSING-MFA", severity: scanner.SeverityHigh, line: 3},
			},
		},
		{
			name: "payment handler function with MFA call in body is clean",
			source: `package test
import "net/http"
func handlePayment(w http.ResponseWriter, r *http.Request) {
	requireMFA(r)
}
func requireMFA(r *http.Request) {}
`,
			expected: nil,
		},
		{
			name: "payment handler function without MFA is HIGH",
			source: `package test
import "net/http"
func handlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("done"))
}
`,
			expected: []expectedFinding{
				{ruleID: "AUTH-MISSING-MFA", severity: scanner.SeverityHigh, line: 3},
			},
		},
		{
			name: "non-HTTP function with payment name is not flagged (Pitfall 4)",
			source: `package test
func processPaymentData(data []byte) {
	_ = data
}
`,
			expected: nil,
		},
		{
			name: "route with variable path is not flagged",
			source: `package test
import "net/http"
func init() {
	path := getPath()
	http.HandleFunc(path, handleSomething)
}
func getPath() string { return "/" }
func handleSomething(w http.ResponseWriter, r *http.Request) {}
`,
			expected: nil,
		},
		{
			name: "payment route with two_factor wrapper is clean",
			source: `package test
import "net/http"
func init() {
	http.HandleFunc("/payment/process", twoFactorAuth(handlePayment))
}
func handlePayment(w http.ResponseWriter, r *http.Request) {}
func twoFactorAuth(h http.HandlerFunc) http.HandlerFunc { return h }
`,
			expected: nil,
		},
		{
			name: "payment handler with otp check in body is clean",
			source: `package test
import "net/http"
func handleCheckout(w http.ResponseWriter, r *http.Request) {
	verifyOTP(r)
}
func verifyOTP(r *http.Request) {}
`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, fset := parseSource(t, tt.source)
			findings := detectMissingMFA(file, fset, "test.go")
			assertFindings(t, findings, tt.expected)
		})
	}
}

func TestPlaceholderDetection(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty string", "", true},
		{"changeme", "changeme", true},
		{"CHANGEME uppercase", "CHANGEME", true},
		{"placeholder", "placeholder", true},
		{"todo", "todo", true},
		{"env template", "${DB_PASSWORD}", true},
		{"angle bracket", "<replace-me>", true},
		{"all-x", "xxxx", true},
		{"all-X uppercase", "XXXX", true},
		{"mixed-x", "xXxX", true},
		{"real password", "secret123", false},
		{"real password long", "my-super-secret-password", false},
		{"partial x", "xtest", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPlaceholder(tt.value); got != tt.want {
				t.Errorf("isPlaceholder(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestIsPasswordName_WordBoundary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// False positives -- MUST NOT match
		{
			name:  "passkeyGroup does not match (pass removed, passkey not a keyword)",
			input: "passkeyGroup",
			want:  false,
		},
		{
			name:  "bypassAuth does not match (no password keyword at boundary)",
			input: "bypassAuth",
			want:  false,
		},
		{
			name:  "rootPwd does not match (pwd removed from keywords)",
			input: "rootPwd",
			want:  false,
		},
		// True positives -- MUST match
		{
			name:  "dbPassword matches (word boundary on password)",
			input: "dbPassword",
			want:  true,
		},
		{
			name:  "userPasswd matches (word boundary on passwd)",
			input: "userPasswd",
			want:  true,
		},
		{
			name:  "myPassphrase matches (word boundary on passphrase)",
			input: "myPassphrase",
			want:  true,
		},
		{
			name:  "dbpass matches (exact match)",
			input: "dbpass",
			want:  true,
		},
		{
			name:  "DB_PASSWORD matches (snake_case boundary)",
			input: "DB_PASSWORD",
			want:  true,
		},
		{
			name:  "newPassword123 does not match (123 suffix is not a value-suffix)",
			input: "newPassword123",
			want:  false,
		},
		{
			name:  "password exact match",
			input: "password",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPasswordName(tt.input)
			if got != tt.want {
				t.Errorf("isPasswordName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// assertFindings checks that actual findings match expected.
func assertFindings(t *testing.T, actual []scanner.Finding, expected []expectedFinding) {
	t.Helper()

	if len(actual) != len(expected) {
		t.Errorf("got %d findings, want %d", len(actual), len(expected))
		for i, f := range actual {
			t.Logf("  finding[%d]: rule=%s severity=%s line=%d desc=%s", i, f.RuleID, f.Severity, f.Line, f.Description)
		}
		return
	}

	for i, exp := range expected {
		if i >= len(actual) {
			break
		}
		f := actual[i]
		if f.RuleID != exp.ruleID {
			t.Errorf("finding[%d].RuleID = %q, want %q", i, f.RuleID, exp.ruleID)
		}
		if f.Severity != exp.severity {
			t.Errorf("finding[%d].Severity = %q, want %q", i, f.Severity, exp.severity)
		}
		if exp.line > 0 && f.Line != exp.line {
			t.Errorf("finding[%d].Line = %d, want %d", i, f.Line, exp.line)
		}
	}
}
