package cryptoscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
)

// writeGoFile creates a Go source file in tmpDir and returns its path.
func writeGoFile(t *testing.T, tmpDir, name, content string) string {
	t.Helper()
	path := filepath.Join(tmpDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", name, err)
	}
	return path
}

func TestEncryptionScanner_Name(t *testing.T) {
	t.Parallel()
	s := cryptoscanner.New()
	if got := s.Name(); got != "encryption" {
		t.Errorf("Name() = %q, want %q", got, "encryption")
	}
}

func TestEncryptionScanner_Requirements(t *testing.T) {
	t.Parallel()
	s := cryptoscanner.New()
	reqs := s.Requirements()
	want := map[string]bool{"6.2.4": true, "4.2.1": true}
	if len(reqs) != len(want) {
		t.Fatalf("Requirements() = %v, want keys %v", reqs, want)
	}
	for _, r := range reqs {
		if !want[r] {
			t.Errorf("Unexpected requirement %q", r)
		}
	}
}

// --- Weak Hash Context Scoring (CRYPTO-01) ---

func TestWeakHash_MD5WithSensitiveContext_Critical(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "hash.go", `package test

import "crypto/md5"

func hashPassword(password string) []byte {
	h := md5.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-WEAK-HASH", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-WEAK-HASH finding for md5 near passwordHash, got findings: %v", result.Findings)
	} else if found.RequirementID != "6.2.4" {
		t.Errorf("Expected requirement 6.2.4, got %s", found.RequirementID)
	}
}

func TestWeakHash_SHA1WithoutContext_Info(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "hash.go", `package test

import "crypto/sha1"

func checksumData(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-WEAK-HASH", scanner.SeverityInfo)
	if found == nil {
		t.Errorf("Expected INFO CRYPTO-WEAK-HASH finding for sha1 without sensitive context, got findings: %v", result.Findings)
	}
	// Should not have CRITICAL for sha1 without context.
	critical := findFinding(result.Findings, "CRYPTO-WEAK-HASH", scanner.SeverityCritical)
	if critical != nil {
		t.Errorf("Did not expect CRITICAL finding for sha1 without sensitive context")
	}
}

func TestWeakHash_SHA256WithPasswordContext_Critical(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "hash.go", `package test

import "crypto/sha256"

func hashUserPassword(passwd string) []byte {
	sum := sha256.Sum256([]byte(passwd))
	return sum[:]
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-WEAK-HASH", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-WEAK-HASH finding for sha256 with password context, got findings: %v", result.Findings)
	}
	// Check suggestion mentions bcrypt/argon2.
	if found != nil && !strings.Contains(strings.ToLower(found.Suggestion), "bcrypt") && !strings.Contains(strings.ToLower(found.Suggestion), "argon2") {
		t.Errorf("Expected suggestion to mention bcrypt or argon2, got: %s", found.Suggestion)
	}
}

func TestWeakHash_SHA256WithoutPasswordContext_NoFindings(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "hash.go", `package test

import "crypto/sha256"

func checksumFile(data []byte) [32]byte {
	return sha256.Sum256(data)
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	hashFindings := filterFindings(result.Findings, "CRYPTO-WEAK-HASH")
	if len(hashFindings) != 0 {
		t.Errorf("Expected zero CRYPTO-WEAK-HASH findings for sha256 without password context, got %d: %v", len(hashFindings), hashFindings)
	}
}

func TestWeakHash_DESNewCipher_AtLeastInfo(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "cipher.go", `package test

import "crypto/des"

func encryptData(data []byte) {
	block, _ := des.NewCipher([]byte("12345678"))
	_ = block
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	hashFindings := filterFindings(result.Findings, "CRYPTO-WEAK-HASH")
	if len(hashFindings) == 0 {
		t.Errorf("Expected at least one CRYPTO-WEAK-HASH finding for des.NewCipher, got none")
	}
}

// --- Hardcoded Key Detection (CRYPTO-02) ---

func TestHardcodedKey_Tier1_KeywordPlusLiteral_Critical(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var secretKey = "mysupersecretkey123"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-HARDCODED-KEY", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-HARDCODED-KEY for keyword+literal, got findings: %v", result.Findings)
	}
}

func TestHardcodedKey_Tier2_HighEntropy_High(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	// 15-05: use a genuinely random-looking fixture. A naive A-Z run would now
	// be filtered by isCharacterSet since an alphabet run of
	// 10+ consecutive letters is treated as a character-set constant.
	writeGoFile(t, tmpDir, "config.go", `package test

var config = "ghp_zX9vQm2tL8jKrB4nYpF6sW1eR7aC"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-HARDCODED-KEY", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-HARDCODED-KEY for high-entropy string (filter Layer 3 upgrade), got findings: %v", result.Findings)
	}
}

func TestHardcodedKey_Tier3_Base64_High(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var data = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-HARDCODED-KEY", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-HARDCODED-KEY for base64 string (filter Layer 3 upgrade), got findings: %v", result.Findings)
	}
}

func TestHardcodedKey_Tier3_Hex_High(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var hexData = "0123456789abcdef0123456789abcdef"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-HARDCODED-KEY", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-HARDCODED-KEY for hex string (filter Layer 3 hex fast-path), got findings: %v", result.Findings)
	}
}

func TestHardcodedKey_Exclusion_ShortString(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var short = "hello"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	keyFindings := filterFindings(result.Findings, "CRYPTO-HARDCODED-KEY")
	if len(keyFindings) != 0 {
		t.Errorf("Expected no CRYPTO-HARDCODED-KEY for short string, got %d: %v", len(keyFindings), keyFindings)
	}
}

func TestHardcodedKey_Exclusion_Semver(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var version = "v1.2.3"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	keyFindings := filterFindings(result.Findings, "CRYPTO-HARDCODED-KEY")
	if len(keyFindings) != 0 {
		t.Errorf("Expected no CRYPTO-HARDCODED-KEY for semver string, got %d: %v", len(keyFindings), keyFindings)
	}
}

func TestHardcodedKey_Exclusion_URL(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var endpoint = "https://example.com/api"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	keyFindings := filterFindings(result.Findings, "CRYPTO-HARDCODED-KEY")
	if len(keyFindings) != 0 {
		t.Errorf("Expected no CRYPTO-HARDCODED-KEY for URL, got %d: %v", len(keyFindings), keyFindings)
	}
}

func TestHardcodedKey_Exclusion_UUID(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var id = "550e8400-e29b-41d4-a716-446655440000"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	keyFindings := filterFindings(result.Findings, "CRYPTO-HARDCODED-KEY")
	if len(keyFindings) != 0 {
		t.Errorf("Expected no CRYPTO-HARDCODED-KEY for UUID, got %d: %v", len(keyFindings), keyFindings)
	}
}

// --- Plain HTTP Detection (CRYPTO-03) ---

func TestPlainHTTP_PaymentURL_Critical(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "api.go", `package test

var apiURL = "http://payment.example.com/api"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	found := findFinding(result.Findings, "CRYPTO-PLAIN-HTTP", scanner.SeverityCritical)
	if found == nil {
		t.Errorf("Expected CRITICAL CRYPTO-PLAIN-HTTP for plain HTTP URL, got findings: %v", result.Findings)
	} else if found.RequirementID != "4.2.1" {
		t.Errorf("Expected requirement 4.2.1, got %s", found.RequirementID)
	}
}

func TestPlainHTTP_Localhost_Excluded(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "api.go", `package test

var devURL = "http://localhost:8080"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	httpFindings := filterFindings(result.Findings, "CRYPTO-PLAIN-HTTP")
	if len(httpFindings) != 0 {
		t.Errorf("Expected no CRYPTO-PLAIN-HTTP for localhost, got %d: %v", len(httpFindings), httpFindings)
	}
}

func TestPlainHTTP_Loopback_Excluded(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "api.go", `package test

var devURL = "http://127.0.0.1:9090"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	httpFindings := filterFindings(result.Findings, "CRYPTO-PLAIN-HTTP")
	if len(httpFindings) != 0 {
		t.Errorf("Expected no CRYPTO-PLAIN-HTTP for 127.0.0.1, got %d: %v", len(httpFindings), httpFindings)
	}
}

func TestPlainHTTP_HTTPS_NoFinding(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "api.go", `package test

var secureURL = "https://secure.example.com"
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	httpFindings := filterFindings(result.Findings, "CRYPTO-PLAIN-HTTP")
	if len(httpFindings) != 0 {
		t.Errorf("Expected no CRYPTO-PLAIN-HTTP for HTTPS URL, got %d: %v", len(httpFindings), httpFindings)
	}
}

// --- Scope Separation (CRYPTO-04) ---

func TestScopeSeparation_TLSConfig_NoFindings(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "tls.go", `package test

import "crypto/tls"

func newTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Should produce zero CRYPTO findings.
	cryptoFindings := filterFindingsPrefix(result.Findings, "CRYPTO-")
	if len(cryptoFindings) != 0 {
		t.Errorf("Expected zero CRYPTO findings for tls.Config code, got %d: %v", len(cryptoFindings), cryptoFindings)
	}
}

// --- Testdata Fixture Verification ---

func TestCryptoViolationsFixture(t *testing.T) {
	t.Parallel()
	// Copy the testdata fixture to a temp dir since the walker always excludes
	// directories named "testdata" via DefaultExcludeDirs.
	fixtureSrc := filepath.Join("..", "..", "testdata", "crypto_violations.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/crypto_violations.go not found, skipping fixture test")
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "crypto_violations.go"), srcBytes, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	// Check for expected violation types.
	if len(result.Findings) == 0 {
		t.Fatal("Expected findings from crypto_violations.go fixture, got none")
	}

	// Verify specific rule types are present.
	hasWeakHash := false
	hasHardcodedKey := false
	hasPlainHTTP := false
	for _, f := range result.Findings {
		switch f.RuleID {
		case "CRYPTO-WEAK-HASH":
			hasWeakHash = true
		case "CRYPTO-HARDCODED-KEY":
			hasHardcodedKey = true
		case "CRYPTO-PLAIN-HTTP":
			hasPlainHTTP = true
		}
	}

	if !hasWeakHash {
		t.Error("Expected CRYPTO-WEAK-HASH finding from fixture")
	}
	if !hasHardcodedKey {
		t.Error("Expected CRYPTO-HARDCODED-KEY finding from fixture")
	}
	if !hasPlainHTTP {
		t.Error("Expected CRYPTO-PLAIN-HTTP finding from fixture")
	}
}

// --- Test PCI-ignore suppression ---

func TestHardcodedKey_PCIIgnore_RawFindingReturned(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	writeGoFile(t, tmpDir, "config.go", `package test

var secretKey = "mysupersecretkey123" // pci-ignore
`)

	s := cryptoscanner.New()
	result, err := s.Scan(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	keyFindings := filterFindings(result.Findings, "CRYPTO-HARDCODED-KEY")
	if len(keyFindings) != 1 {
		t.Errorf("Expected 1 CRYPTO-HARDCODED-KEY (suppression now centralized), got %d", len(keyFindings))
	}
}

// --- Helper functions ---

func findFinding(findings []scanner.Finding, ruleID string, severity scanner.Severity) *scanner.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID && findings[i].Severity == severity {
			return &findings[i]
		}
	}
	return nil
}

func filterFindings(findings []scanner.Finding, ruleID string) []scanner.Finding {
	var result []scanner.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			result = append(result, f)
		}
	}
	return result
}

func filterFindingsPrefix(findings []scanner.Finding, prefix string) []scanner.Finding {
	var result []scanner.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, prefix) {
			result = append(result, f)
		}
	}
	return result
}
