package scriptscanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// copyFixture copies a testdata fixture to a temp directory for scanning.
func copyFixture(t *testing.T, srcPath string) string {
	t.Helper()
	content, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", srcPath, err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, filepath.Base(srcPath))
	if err := os.WriteFile(dst, content, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// writeHTMLFixture writes HTML content to a temp directory and returns the directory.
func writeHTMLFixture(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// scanHTML is a helper that scans a directory and returns findings.
func scanHTML(t *testing.T, dir string) []scanner.Finding {
	t.Helper()
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	return result.Findings
}

// violationsFixturePath returns the absolute path to the violations test fixture.
func violationsFixturePath(t *testing.T) string {
	t.Helper()
	// Go test working directory is the package directory.
	// Navigate up to the repo root to find testdata/.
	path, err := filepath.Abs("../../testdata/script_violations.html")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return path
}

// cleanFixturePath returns the absolute path to the clean test fixture.
func cleanFixturePath(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs("../../testdata/script_clean.html")
	if err != nil {
		t.Fatalf("Abs: %v", err)
	}
	return path
}

// TestSRIMissing verifies SRI-MISSING-PAYMENT findings for external scripts
// without integrity attribute in a payment template (CRITICAL).
func TestSRIMissing(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, violationsFixturePath(t))
	findings := scanHTML(t, dir)

	sriMissing := findByRule(findings, "SRI-MISSING-PAYMENT")
	// Expect at least 2: payment-sdk.js and track.js (ga.js is inside Go template, may also be found)
	if len(sriMissing) < 2 {
		t.Fatalf("Expected at least 2 SRI-MISSING-PAYMENT findings, got %d: %+v", len(sriMissing), sriMissing)
	}

	for _, f := range sriMissing {
		if f.Severity != scanner.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for SRI-MISSING-PAYMENT, got %s for %s", f.Severity, f.Description)
		}
		if f.RequirementID != "6.4.3" {
			t.Errorf("Expected requirement 6.4.3, got %s", f.RequirementID)
		}
	}
}

// TestInlineNoNonce verifies NONCE-MISSING-PAYMENT finding for inline script
// without nonce in a payment template (CRITICAL).
func TestInlineNoNonce(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, violationsFixturePath(t))
	findings := scanHTML(t, dir)

	nonceMissing := findByRule(findings, "NONCE-MISSING-PAYMENT")
	if len(nonceMissing) < 1 {
		t.Fatalf("Expected at least 1 NONCE-MISSING-PAYMENT finding, got %d: %+v", len(nonceMissing), nonceMissing)
	}

	for _, f := range nonceMissing {
		if f.Severity != scanner.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for NONCE-MISSING-PAYMENT, got %s", f.Severity)
		}
		if f.RequirementID != "6.4.3" {
			t.Errorf("Expected requirement 6.4.3, got %s", f.RequirementID)
		}
	}
}

// TestSRIPresent verifies that a script with integrity attribute does NOT
// produce SRI-MISSING findings.
func TestSRIPresent(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, violationsFixturePath(t))
	findings := scanHTML(t, dir)

	// The verified.js script has integrity= so should NOT appear.
	for _, f := range findings {
		if f.RuleID == "SRI-MISSING" || f.RuleID == "SRI-MISSING-PAYMENT" {
			if f.Description != "" && contains(f.Description, "verified.js") {
				t.Errorf("Script with integrity attribute should not be flagged: %+v", f)
			}
		}
	}
}

// TestNoncePresent verifies that an inline script with nonce attribute does
// NOT produce NONCE-MISSING findings.
func TestNoncePresent(t *testing.T) {
	t.Parallel()
	html := `<!DOCTYPE html>
<html><body>
<script nonce="abc123">console.log("safe");</script>
</body></html>`
	dir := writeHTMLFixture(t, "safe.html", html)
	findings := scanHTML(t, dir)

	nonceMissing := findByRule(findings, "NONCE-MISSING")
	nonceMissingPayment := findByRule(findings, "NONCE-MISSING-PAYMENT")
	if len(nonceMissing)+len(nonceMissingPayment) != 0 {
		t.Errorf("Expected 0 NONCE-MISSING findings for script with nonce, got %d",
			len(nonceMissing)+len(nonceMissingPayment))
	}
}

// TestMetaCSPUnsafe verifies META-CSP-UNSAFE finding for meta tag with
// unsafe-inline.
func TestMetaCSPUnsafe(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, violationsFixturePath(t))
	findings := scanHTML(t, dir)

	metaUnsafe := findByRule(findings, "META-CSP-UNSAFE")
	if len(metaUnsafe) != 1 {
		t.Fatalf("Expected 1 META-CSP-UNSAFE finding, got %d: %+v", len(metaUnsafe), findings)
	}
	if metaUnsafe[0].Severity != scanner.SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", metaUnsafe[0].Severity)
	}
	if metaUnsafe[0].RequirementID != "6.4.3" {
		t.Errorf("Expected requirement 6.4.3, got %s", metaUnsafe[0].RequirementID)
	}
}

// TestFIMRequired verifies FIM-REQUIRED finding is emitted for payment
// templates.
func TestFIMRequired(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, violationsFixturePath(t))
	findings := scanHTML(t, dir)

	fim := findByRule(findings, "FIM-REQUIRED")
	if len(fim) != 1 {
		t.Fatalf("Expected 1 FIM-REQUIRED finding, got %d: %+v", len(fim), findings)
	}
	if fim[0].Severity != scanner.SeverityMedium {
		t.Errorf("Expected MEDIUM severity, got %s", fim[0].Severity)
	}
	if fim[0].RequirementID != "11.6.1" {
		t.Errorf("Expected requirement 11.6.1, got %s", fim[0].RequirementID)
	}
}

// TestCleanHTML verifies that a clean HTML file with proper SRI and nonces
// produces zero HIGH/CRITICAL findings. Only FIM-REQUIRED MEDIUM is expected.
func TestCleanHTML(t *testing.T) {
	t.Parallel()
	dir := copyFixture(t, cleanFixturePath(t))
	findings := scanHTML(t, dir)

	for _, f := range findings {
		if f.Severity == scanner.SeverityHigh || f.Severity == scanner.SeverityCritical {
			t.Errorf("Unexpected %s finding in clean HTML: %+v", f.Severity, f)
		}
	}

	// Should still get FIM-REQUIRED since it has payment keywords (card-number input).
	fim := findByRule(findings, "FIM-REQUIRED")
	if len(fim) != 1 {
		t.Errorf("Expected 1 FIM-REQUIRED finding for clean payment template, got %d", len(fim))
	}
}

// TestGoTemplateSyntax verifies that HTML files containing Go template {{ }}
// syntax do not cause parse errors.
func TestGoTemplateSyntax(t *testing.T) {
	t.Parallel()
	html := `<!DOCTYPE html>
<html><head><title>Template Test</title></head>
<body>
{{ if .ShowBanner }}
<div class="banner">{{ .BannerText }}</div>
{{ end }}
{{ range .Items }}
<p>{{ .Name }}</p>
{{ end }}
<script src="https://cdn.example.com/app.js"
        integrity="sha384-abc123"
        crossorigin="anonymous"></script>
</body></html>`
	dir := writeHTMLFixture(t, "template.html", html)
	findings := scanHTML(t, dir)

	// Should NOT produce any errors; the file should be scannable.
	// External script has integrity, so no SRI-MISSING.
	sriMissing := findByRule(findings, "SRI-MISSING")
	sriMissingPayment := findByRule(findings, "SRI-MISSING-PAYMENT")
	if len(sriMissing)+len(sriMissingPayment) != 0 {
		t.Errorf("Expected 0 SRI-MISSING findings for script with integrity, got %d",
			len(sriMissing)+len(sriMissingPayment))
	}
}

// TestNonPaymentTemplate verifies that external scripts without SRI in a
// non-payment template get HIGH (not CRITICAL) severity.
func TestNonPaymentTemplate(t *testing.T) {
	t.Parallel()
	html := `<!DOCTYPE html>
<html><head><title>About Page</title></head>
<body>
<h1>About Us</h1>
<p>No payment forms here.</p>
<script src="https://cdn.example.com/analytics.js"></script>
<script>console.log("inline without nonce");</script>
</body></html>`
	dir := writeHTMLFixture(t, "about.html", html)
	findings := scanHTML(t, dir)

	// Should get HIGH, not CRITICAL (no payment keywords).
	sriMissing := findByRule(findings, "SRI-MISSING")
	if len(sriMissing) != 1 {
		t.Fatalf("Expected 1 SRI-MISSING finding, got %d: %+v", len(sriMissing), findings)
	}
	if sriMissing[0].Severity != scanner.SeverityHigh {
		t.Errorf("Expected HIGH severity for non-payment template, got %s", sriMissing[0].Severity)
	}

	nonceMissing := findByRule(findings, "NONCE-MISSING")
	if len(nonceMissing) != 1 {
		t.Fatalf("Expected 1 NONCE-MISSING finding, got %d: %+v", len(nonceMissing), findings)
	}
	if nonceMissing[0].Severity != scanner.SeverityHigh {
		t.Errorf("Expected HIGH severity for non-payment template, got %s", nonceMissing[0].Severity)
	}

	// No FIM-REQUIRED (not a payment page).
	fim := findByRule(findings, "FIM-REQUIRED")
	if len(fim) != 0 {
		t.Errorf("Expected 0 FIM-REQUIRED findings for non-payment template, got %d", len(fim))
	}

	// No -PAYMENT variants.
	sriPayment := findByRule(findings, "SRI-MISSING-PAYMENT")
	noncePayment := findByRule(findings, "NONCE-MISSING-PAYMENT")
	if len(sriPayment)+len(noncePayment) != 0 {
		t.Errorf("Expected 0 -PAYMENT findings for non-payment template, got %d",
			len(sriPayment)+len(noncePayment))
	}
}

// TestMetaCSPOnly verifies META-CSP-ONLY finding for a meta CSP without
// unsafe patterns.
func TestMetaCSPOnly(t *testing.T) {
	t.Parallel()
	html := `<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Security-Policy" content="script-src 'self'">
</head><body>
<script src="https://cdn.example.com/app.js"
        integrity="sha384-abc123"
        crossorigin="anonymous"></script>
</body></html>`
	dir := writeHTMLFixture(t, "metacsp.html", html)
	findings := scanHTML(t, dir)

	metaOnly := findByRule(findings, "META-CSP-ONLY")
	if len(metaOnly) != 1 {
		t.Fatalf("Expected 1 META-CSP-ONLY finding, got %d: %+v", len(metaOnly), findings)
	}
	if metaOnly[0].Severity != scanner.SeverityMedium {
		t.Errorf("Expected MEDIUM severity, got %s", metaOnly[0].Severity)
	}
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
