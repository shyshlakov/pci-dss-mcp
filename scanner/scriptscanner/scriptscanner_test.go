package scriptscanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// writeFixture writes Go source code to a temp directory and returns the directory path.
func writeFixture(t *testing.T, filename, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// findByRule returns findings matching the given ruleID.
func findByRule(findings []scanner.Finding, ruleID string) []scanner.Finding {
	var matched []scanner.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			matched = append(matched, f)
		}
	}
	return matched
}

// findBySeverity returns findings matching the given severity.
func findBySeverity(findings []scanner.Finding, sev scanner.Severity) []scanner.Finding {
	var matched []scanner.Finding
	for _, f := range findings {
		if f.Severity == sev {
			matched = append(matched, f)
		}
	}
	return matched
}

// TestCSPHeaderMissing_UnknownResponseType verifies CSP-MISSING is reported at INFO severity
// for a payment handler with unknown response type.
func TestCSPHeaderMissing_UnknownResponseType(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment form"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 1 {
		t.Fatalf("Expected 1 CSP-MISSING finding, got %d: %+v", len(missing), result.Findings)
	}
	// unknown response type -> INFO severity with "verify CSP" message.
	if missing[0].Severity != scanner.SeverityInfo {
		t.Errorf("Expected INFO severity for unknown response type, got %s", missing[0].Severity)
	}
	if missing[0].RequirementID != "6.4.3" {
		t.Errorf("Expected requirement 6.4.3, got %s", missing[0].RequirementID)
	}
	if !strings.Contains(missing[0].Description, "verify CSP") {
		t.Errorf("Expected description to mention 'verify CSP', got: %s", missing[0].Description)
	}
	if !strings.Contains(missing[0].Description, "HandlePayment") {
		t.Errorf("Expected description to mention handler name, got: %s", missing[0].Description)
	}
}

// TestCSPHeaderMissing_HTMLHandler verifies CSP-MISSING is reported at HIGH severity
// for a payment handler that serves HTML.
func TestCSPHeaderMissing_HTMLHandler(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html>payment form</html>"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 1 {
		t.Fatalf("Expected 1 CSP-MISSING finding for HTML handler, got %d: %+v", len(missing), result.Findings)
	}
	if missing[0].Severity != scanner.SeverityHigh {
		t.Errorf("Expected HIGH severity for HTML handler, got %s", missing[0].Severity)
	}
	if !strings.Contains(missing[0].Description, "6.4.3") {
		t.Errorf("Expected description to mention 6.4.3, got: %s", missing[0].Description)
	}
}

// TestCSPHeaderMissing_JSONHandler verifies CSP-MISSING is NOT emitted
// for a JSON API handler.
func TestCSPHeaderMissing_JSONHandler(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"encoding/json"
	"net/http"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// JSON handlers should produce zero CSP findings.
	for _, f := range result.Findings {
		if strings.HasPrefix(f.RuleID, "CSP-") {
			t.Errorf("Expected no CSP findings for JSON handler, got: %+v", f)
		}
	}
}

// TestUnsafeCSP verifies CSP-UNSAFE-INLINE, CSP-UNSAFE-EVAL, and
// CSP-NO-SCRIPT-SRC findings for handlers with weak CSP.
func TestUnsafeCSP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		src       string
		wantRule  string
		wantCount int
	}{
		{
			name: "unsafe-inline",
			src: `package test

import "net/http"

func HandleCheckout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")
	w.Write([]byte("checkout"))
}
`,
			wantRule:  "CSP-UNSAFE-INLINE",
			wantCount: 1,
		},
		{
			name: "unsafe-eval",
			src: `package test

import "net/http"

func ProcessTransaction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'self' 'unsafe-eval'")
	w.Write([]byte("transaction"))
}
`,
			wantRule:  "CSP-UNSAFE-EVAL",
			wantCount: 1,
		},
		{
			name: "no script-src or default-src",
			src: `package test

import "net/http"

func HandleRefund(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "img-src 'self'; font-src 'self'")
	w.Write([]byte("refund"))
}
`,
			wantRule:  "CSP-NO-SCRIPT-SRC",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFixture(t, "handler.go", tt.src)
			s := New()
			result, err := s.ScanWithExclusions(context.Background(), dir, nil)
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}

			matched := findByRule(result.Findings, tt.wantRule)
			if len(matched) != tt.wantCount {
				t.Errorf("Expected %d %s findings, got %d: %+v",
					tt.wantCount, tt.wantRule, len(matched), result.Findings)
			}
			for _, f := range matched {
				if f.Severity != scanner.SeverityHigh {
					t.Errorf("Expected HIGH severity for %s, got %s", tt.wantRule, f.Severity)
				}
			}
		})
	}
}

// TestCSPNonceOverride verifies that unsafe-inline is NOT flagged when a
// nonce is present (CSP3 spec).
func TestCSPNonceOverride(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandleCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'nonce-abc123' 'unsafe-inline'")
	w.Write([]byte("card"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	unsafeInline := findByRule(result.Findings, "CSP-UNSAFE-INLINE")
	if len(unsafeInline) != 0 {
		t.Errorf("Expected 0 CSP-UNSAFE-INLINE findings (nonce overrides), got %d: %+v",
			len(unsafeInline), unsafeInline)
	}

	// Should get CSP-OK instead.
	ok := findByRule(result.Findings, "CSP-OK")
	if len(ok) != 1 {
		t.Errorf("Expected 1 CSP-OK finding, got %d: %+v", len(ok), result.Findings)
	}
}

// TestCSPSameFileHelper verifies that CSP set in a same-file helper function
// is detected (1-level resolution).
func TestCSPSameFileHelper(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandleBilling(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Write([]byte("billing"))
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "script-src 'self'")
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 0 {
		t.Errorf("Expected 0 CSP-MISSING findings (helper sets CSP), got %d: %+v",
			len(missing), missing)
	}

	// Should get CSP-OK for the billing handler.
	ok := findByRule(result.Findings, "CSP-OK")
	if len(ok) != 1 {
		t.Errorf("Expected 1 CSP-OK finding, got %d: %+v", len(ok), result.Findings)
	}
}

// TestCSPNonPaymentHandlerSkipped verifies that non-payment handlers produce
// no findings at all.
func TestCSPNonPaymentHandlerSkipped(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}

func HandleAbout(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("about"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for non-payment handlers, got %d: %+v",
			len(result.Findings), result.Findings)
	}
}

// TestCSPCleanHandlers verifies that handlers with proper CSP produce only
// INFO findings (CSP-OK), no HIGH findings.
func TestCSPCleanHandlers(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandlePaymentClean(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	w.Write([]byte("payment"))
}

func HandleCheckoutClean(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'nonce-random123'")
	w.Write([]byte("checkout"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings for clean handlers, got %d: %+v", len(high), high)
	}

	ok := findByRule(result.Findings, "CSP-OK")
	if len(ok) != 2 {
		t.Errorf("Expected 2 CSP-OK findings, got %d: %+v", len(ok), result.Findings)
	}
}

// TestCSPUnanalyzableValue verifies that a CSP header with a variable value
// (not a string literal) produces a CSP-VALUE-UNANALYZABLE finding.
func TestCSPUnanalyzableValue(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

var cspPolicy = "script-src 'self'"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", cspPolicy)
	w.Write([]byte("payment"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	unanalyzable := findByRule(result.Findings, "CSP-VALUE-UNANALYZABLE")
	if len(unanalyzable) != 1 {
		t.Fatalf("Expected 1 CSP-VALUE-UNANALYZABLE finding, got %d: %+v",
			len(unanalyzable), result.Findings)
	}
	if unanalyzable[0].Severity != scanner.SeverityInfo {
		t.Errorf("Expected INFO severity, got %s", unanalyzable[0].Severity)
	}
}

// TestCSPGinHandler verifies CSP detection works for gin framework handlers.
// Uses c.HTML() (not c.JSON()) because JSON API handlers are correctly skipped
// by response type detection -- CSP is only required for HTML responses.
func TestCSPGinHandler(t *testing.T) {
	t.Parallel()
	src := `package test

import "github.com/gin-gonic/gin"

func HandlePayment(c *gin.Context) {
	c.Header("Content-Security-Policy", "script-src 'self'")
	c.HTML(200, "payment.html", gin.H{"status": "ok"})
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	ok := findByRule(result.Findings, "CSP-OK")
	if len(ok) != 1 {
		t.Errorf("Expected 1 CSP-OK finding for gin handler, got %d: %+v", len(ok), result.Findings)
	}
}

// TestCSPGinJSONHandlerSkipped verifies that Gin JSON API handlers are correctly
// skipped by CSP check -- JSON APIs don't serve HTML and don't need CSP headers.
func TestCSPGinJSONHandlerSkipped(t *testing.T) {
	t.Parallel()
	src := `package test

import "github.com/gin-gonic/gin"

func HandlePayment(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for JSON API handler, got %d: %+v", len(result.Findings), result.Findings)
	}
}

// TestScannerInterface verifies ScriptScanner implements scanner.Scanner.
func TestScannerInterface(t *testing.T) {
	t.Parallel()
	s := New()

	if name := s.Name(); name != "payment_page_scripts" {
		t.Errorf("Name() = %q, want %q", name, "payment_page_scripts")
	}

	if desc := s.Description(); desc == "" {
		t.Error("Description() should not be empty")
	}

	reqs := s.Requirements()
	if len(reqs) < 2 {
		t.Errorf("Requirements() should return at least 2 requirements, got %d", len(reqs))
	}

	// Verify interface compliance.
	var _ scanner.Scanner = s
}

// TestCSPMetadata verifies that scan metadata is populated correctly.
func TestCSPMetadata(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if result.Metadata.ScannedFiles == 0 {
		t.Error("Expected ScannedFiles > 0")
	}
	if result.Metadata.ScannedLines == 0 {
		t.Error("Expected ScannedLines > 0")
	}
}

// writeFixtureAtSubdir writes a Go source file under a nested subdirectory
// of a fresh temp dir and returns the temp-dir root. Useful for simulating
// directory-based filters such as "/callback/".
func writeFixtureAtSubdir(t *testing.T, subdir, filename, src string) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, subdir)
	if err := os.MkdirAll(full, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(full, filename), []byte(src), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return root
}

// TestScriptScanner_CallbackNameSuffixSuppressesCSPMissingInfo verifies
// rule 1: a payment handler whose name ends with "Callback" does not emit
// CSP-MISSING INFO when response type is unknown.
func TestScriptScanner_CallbackNameSuffixSuppressesCSPMissingInfo(t *testing.T) {
	t.Parallel()
	src := `package callbacktest

import "net/http"

func MastercardCallback(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 0 {
		t.Errorf("Expected 0 CSP-MISSING findings for S2S callback by name suffix, got %d: %+v",
			len(missing), missing)
	}
}

// TestScriptScanner_CallbackDirSuppressesCSPMissingInfo verifies rule 3:
// a payment handler living under a callback/ directory does not emit
// CSP-MISSING INFO when response type is unknown.
func TestScriptScanner_CallbackDirSuppressesCSPMissingInfo(t *testing.T) {
	t.Parallel()
	src := `package callbacktest

import "net/http"

func HandlePaymentNotify(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}
`
	root := writeFixtureAtSubdir(t, "internal/http/handler/callback", "mastercard.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 0 {
		t.Errorf("Expected 0 CSP-MISSING findings for handler under callback/ dir, got %d: %+v",
			len(missing), missing)
	}
}

// TestScriptScanner_CallbackRouteSuppressesCSPMissingInfo verifies
// rule 2: a payment handler registered on a /callback/ route does not emit
// CSP-MISSING INFO when response type is unknown.
func TestScriptScanner_CallbackRouteSuppressesCSPMissingInfo(t *testing.T) {
	t.Parallel()
	src := `package apitest

import "net/http"

type Router struct{}

func (r *Router) POST(path string, h http.HandlerFunc) {}

func Register(router *Router) {
	router.POST("/callback/mastercard", HandlePaymentNotify)
}

func HandlePaymentNotify(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 0 {
		t.Errorf("Expected 0 CSP-MISSING findings for handler on /callback/ route, got %d: %+v",
			len(missing), missing)
	}
}

// TestScriptScanner_PaymentHandlerOutsideCallbackStillFiresInfo is the
// no-regression guard: a payment handler with unknown response type and no
// callback signal must STILL emit CSP-MISSING at INFO severity.
func TestScriptScanner_PaymentHandlerOutsideCallbackStillFiresInfo(t *testing.T) {
	t.Parallel()
	src := `package normaltest

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("payment"))
}
`
	root := writeFixtureAtSubdir(t, "internal/http/handler", "pay.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 1 {
		t.Fatalf("Expected 1 CSP-MISSING INFO finding for non-callback unknown-type handler, got %d: %+v",
			len(missing), result.Findings)
	}
	if missing[0].Severity != scanner.SeverityInfo {
		t.Errorf("Expected INFO severity, got %s", missing[0].Severity)
	}
}

// TestScriptScanner_HTMLHandlerStillFiresHigh is the spoofing guard:
// if the handler KNOWN to render HTML lives inside a callback/ directory
// OR has a Callback-suffixed name, CSP-MISSING must still fire at HIGH
// severity. Suppression only applies to the unknown-type branch.
func TestScriptScanner_HTMLHandlerStillFiresHigh(t *testing.T) {
	t.Parallel()
	src := `package callbacktest

import "net/http"

func HandlePaymentNotify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, _ = w.Write([]byte("<html>payment</html>"))
}
`
	root := writeFixtureAtSubdir(t, "internal/http/handler/callback", "mastercard.go", src)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), root, nil)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	missing := findByRule(result.Findings, "CSP-MISSING")
	if len(missing) != 1 {
		t.Fatalf("Expected 1 CSP-MISSING HIGH finding (HTML handler inside callback/ still flagged), got %d: %+v",
			len(missing), result.Findings)
	}
	if missing[0].Severity != scanner.SeverityHigh {
		t.Errorf("Expected HIGH severity for HTML handler even inside callback/, got %s", missing[0].Severity)
	}
}
