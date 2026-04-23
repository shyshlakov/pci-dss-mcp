package tlsscanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// writeGoFile writes a Go source file in a temp directory and returns the dir path.
func writeGoFile(t *testing.T, filename, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// findByRule returns all findings matching the given rule ID.
func findByRule(findings []scanner.Finding, ruleID string) []scanner.Finding {
	var matched []scanner.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			matched = append(matched, f)
		}
	}
	return matched
}

// --- TLSScanner interface tests ---

func TestTLSScanner_Name(t *testing.T) {
	t.Parallel()
	s := New()
	if got := s.Name(); got != "tls_config" {
		t.Errorf("Name() = %q, want %q", got, "tls_config")
	}
}

func TestTLSScanner_Requirements(t *testing.T) {
	t.Parallel()
	s := New()
	reqs := s.Requirements()
	if len(reqs) != 1 || reqs[0] != "4.2.1" {
		t.Errorf("Requirements() = %v, want [4.2.1]", reqs)
	}
}

// --- InsecureSkipVerify tests (TLS-01) ---

func TestInsecureSkipVerify_CompositeLiteral_True(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: true}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-INSECURE-SKIP-VERIFY finding for InsecureSkipVerify: true")
	}
	if findings[0].Severity != scanner.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", findings[0].Severity)
	}
	if findings[0].RequirementID != "4.2.1" {
		t.Errorf("RequirementID = %q, want 4.2.1", findings[0].RequirementID)
	}
}

func TestInsecureSkipVerify_CompositeLiteral_False(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: false, MinVersion: tls.VersionTLS12}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-INSECURE-SKIP-VERIFY finding for false, got %d", len(findings))
	}
}

func TestInsecureSkipVerify_FieldAssignment_True(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
func f() {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	cfg.InsecureSkipVerify = true
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-INSECURE-SKIP-VERIFY finding for field assignment = true")
	}
	if findings[0].Severity != scanner.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", findings[0].Severity)
	}
}

func TestInsecureSkipVerify_FieldAssignment_False(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
func f() {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	cfg.InsecureSkipVerify = false
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-INSECURE-SKIP-VERIFY finding for false assignment, got %d", len(findings))
	}
}

func TestInsecureSkipVerify_NotPresent(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS12}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-INSECURE-SKIP-VERIFY for absent field, got %d", len(findings))
	}
}

// --- MinVersion tests (TLS-02) ---

func TestWeakMinVersion_TLS10(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS10}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-VERSION finding for VersionTLS10")
	}
	if findings[0].Severity != scanner.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", findings[0].Severity)
	}
}

func TestWeakMinVersion_TLS11(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS11}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-VERSION finding for VersionTLS11")
	}
}

func TestWeakMinVersion_SSL30(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionSSL30}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-VERSION finding for VersionSSL30")
	}
}

func TestMinVersion_TLS12_NoFinding(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS12}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-WEAK-VERSION finding for TLS12, got %d", len(findings))
	}
}

func TestMinVersion_TLS13_NoFinding(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS13}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-WEAK-VERSION finding for TLS13, got %d", len(findings))
	}
}

// --- Missing MinVersion tests ---

func TestMissingMinVersion_ConfigWithoutIt(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{InsecureSkipVerify: false}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-MISSING-MIN-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-MISSING-MIN-VERSION finding when MinVersion is absent")
	}
	if findings[0].Severity != scanner.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", findings[0].Severity)
	}
}

func TestMissingMinVersion_WithMinVersion_NoFinding(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS12}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-MISSING-MIN-VERSION")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-MISSING-MIN-VERSION when MinVersion is set, got %d", len(findings))
	}
}

func TestMissingMinVersion_EmptyConfig(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-MISSING-MIN-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-MISSING-MIN-VERSION finding for empty tls.Config{}")
	}
	if findings[0].Severity != scanner.SeverityHigh {
		t.Errorf("Severity = %q, want HIGH", findings[0].Severity)
	}
}

// --- Cipher suite tests (TLS-03) ---

func TestWeakCipher_RC4(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-CIPHER")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-CIPHER finding for RC4 cipher suite")
	}
	if findings[0].Severity != scanner.SeverityCritical {
		t.Errorf("Severity = %q, want CRITICAL", findings[0].Severity)
	}
}

func TestWeakCipher_3DES(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-CIPHER")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-CIPHER finding for 3DES cipher suite")
	}
}

func TestWeakCipher_RC4_ECDHE(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA},
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-CIPHER")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-CIPHER finding for ECDHE_RSA_WITH_RC4 cipher suite")
	}
}

func TestSafeCipher_AES_CBC_NoFinding(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-CIPHER")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-WEAK-CIPHER for AES-CBC, got %d", len(findings))
	}
}

func TestSafeCipher_ChaCha20_NoFinding(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{
	MinVersion: tls.VersionTLS12,
	CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-CIPHER")
	if len(findings) != 0 {
		t.Errorf("Expected no TLS-WEAK-CIPHER for ChaCha20, got %d", len(findings))
	}
}

// --- Scope separation tests (TLS-04) ---

func TestScopeSeparation_OnlyCryptoUsage_ZeroTLSFindings(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import (
	"crypto/md5"
	"crypto/sha1"
)
func hash() {
	_ = md5.New()
	_ = sha1.Sum(nil)
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("Expected zero TLS findings for application-level crypto, got %d", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  Unexpected finding: %s %s at line %d", f.RuleID, f.Severity, f.Line)
		}
	}
}

// --- Import alias tests ---

func TestImportAlias_ResolvedCorrectly(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import ctls "crypto/tls"
var c = &ctls.Config{InsecureSkipVerify: true}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-INSECURE-SKIP-VERIFY finding when import alias is used")
	}
}

// --- MinVersion field assignment tests ---

func TestWeakMinVersion_FieldAssignment(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
func f() {
	cfg := &tls.Config{}
	cfg.MinVersion = tls.VersionTLS10
}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	findings := findByRule(result.Findings, "TLS-WEAK-VERSION")
	if len(findings) == 0 {
		t.Fatal("Expected TLS-WEAK-VERSION finding for MinVersion field assignment")
	}
}

// --- Ciphers unit tests ---

func TestIsProhibitedCipher(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"TLS_RSA_WITH_RC4_128_SHA", true},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", true},
		{"TLS_ECDHE_RSA_WITH_RC4_128_SHA", true},
		{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false},
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false},
		{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", false},
		{"TLS_RSA_WITH_AES_256_GCM_SHA384", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isProhibitedCipher(tt.name); got != tt.want {
				t.Errorf("isProhibitedCipher(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsWeakTLSVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		want bool
	}{
		{"VersionSSL30", true},
		{"VersionTLS10", true},
		{"VersionTLS11", true},
		{"VersionTLS12", false},
		{"VersionTLS13", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isWeakTLSVersion(tt.name); got != tt.want {
				t.Errorf("isWeakTLSVersion(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// --- Fixture file test ---

func TestFixtureFile_Violations(t *testing.T) {
	t.Parallel()
	// Scan the testdata/tls_violations.go fixture directly.
	// The fixture is at the project root's testdata/ directory.
	// We need to find it relative to the test.
	fixtureDir := filepath.Join("..", "..", "testdata")
	info, err := os.Stat(fixtureDir)
	if err != nil || !info.IsDir() {
		t.Skipf("testdata directory not found at %s, skipping fixture test", fixtureDir)
	}

	// Write a copy of the fixture to a temp dir (without build tag, so it parses).
	fixtureContent, err := os.ReadFile(filepath.Join(fixtureDir, "tls_violations.go"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Remove the build tag so it parses as normal Go.
	content := strings.Replace(string(fixtureContent), "//go:build ignore\n\n", "", 1)
	dir := writeGoFile(t, "tls_violations.go", content)

	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}

	// Count expected violations by rule ID.
	insecureSkip := findByRule(result.Findings, "TLS-INSECURE-SKIP-VERIFY")
	weakVersion := findByRule(result.Findings, "TLS-WEAK-VERSION")
	missingVersion := findByRule(result.Findings, "TLS-MISSING-MIN-VERSION")
	weakCipher := findByRule(result.Findings, "TLS-WEAK-CIPHER")

	// At minimum:
	// 2 InsecureSkipVerify (composite literal + field assignment)
	if len(insecureSkip) < 2 {
		t.Errorf("Expected at least 2 TLS-INSECURE-SKIP-VERIFY findings, got %d", len(insecureSkip))
	}
	// 3 weak versions (TLS10, TLS11, SSL30)
	if len(weakVersion) < 3 {
		t.Errorf("Expected at least 3 TLS-WEAK-VERSION findings, got %d", len(weakVersion))
	}
	// At least 2 missing min version (insecure client config + empty config)
	if len(missingVersion) < 2 {
		t.Errorf("Expected at least 2 TLS-MISSING-MIN-VERSION findings, got %d", len(missingVersion))
	}
	// 2 weak ciphers (RC4, 3DES)
	if len(weakCipher) < 2 {
		t.Errorf("Expected at least 2 TLS-WEAK-CIPHER findings, got %d", len(weakCipher))
	}

	t.Logf("Fixture findings: %d insecureSkip, %d weakVersion, %d missingVersion, %d weakCipher",
		len(insecureSkip), len(weakVersion), len(missingVersion), len(weakCipher))
}

// --- Metadata tests ---

func TestScanMetadata(t *testing.T) {
	t.Parallel()
	dir := writeGoFile(t, "test.go", `package test
import "crypto/tls"
var c = &tls.Config{MinVersion: tls.VersionTLS12}
`)
	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}
	if result.Metadata.ScannedFiles != 1 {
		t.Errorf("ScannedFiles = %d, want 1", result.Metadata.ScannedFiles)
	}
	if result.Metadata.ScannedLines == 0 {
		t.Error("ScannedLines should be > 0")
	}
}
