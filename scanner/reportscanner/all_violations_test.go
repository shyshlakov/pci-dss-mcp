package reportscanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/auditscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/authscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/errorscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/retentionscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/tlsscanner"
)

// TestAllViolationsFixture verifies that every Go-based scanner detects at least
// one violation in the comprehensive all_violations test fixtures.
//
// This serves as a regression safety net: any scanner change that breaks detection
// will be caught immediately. depscanner is excluded because it requires go.mod
// at the target path.
//
// Strategy: copy all_violations.* fixtures to a temp directory (because DefaultExcludeDirs
// skips "testdata"), then run each scanner with ScanWithExclusions(nil) against the temp dir.
func TestAllViolationsFixture(t *testing.T) {
	ctx := context.Background()

	// Copy all fixtures to a temp dir to bypass "testdata" exclusion.
	tmpDir := t.TempDir()
	fixtureDir := filepath.Join("..", "..", "testdata")

	fixtures := []string{
		"all_violations.go",
		"all_violations.html",
		"all_violations.env",
		"all_violations.json",
		"all_violations.yaml",
	}

	for _, f := range fixtures {
		src := filepath.Join(fixtureDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", f, err)
		}
		dst := filepath.Join(tmpDir, f)
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("failed to write fixture %s: %v", f, err)
		}
	}

	// Define scanners to test (all 9 Go-based scanners, excluding depscanner).
	type scannerEntry struct {
		name    string
		scanner interface {
			ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error)
		}
		minFindings int
	}

	scanners := []scannerEntry{
		{"pan", panscanner.New(), 1},
		{"crypto", cryptoscanner.New(), 1},
		{"tls", tlsscanner.New(), 1},
		{"error", errorscanner.New(), 1},
		{"secret", secretscanner.New(), 1},
		{"auth", authscanner.New(), 1},
		{"audit", auditscanner.New(), 1},
		{"retention", retentionscanner.New(), 1},
		{"script", scriptscanner.New(), 1},
	}

	for _, tc := range scanners {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.scanner.ScanWithExclusions(ctx, tmpDir, nil)
			if err != nil {
				t.Fatalf("%s scanner error: %v", tc.name, err)
			}
			if len(result.Findings) < tc.minFindings {
				t.Errorf("%s scanner: expected at least %d findings, got %d",
					tc.name, tc.minFindings, len(result.Findings))
				for _, f := range result.Findings {
					t.Logf("  finding: %s %s %s", f.RuleID, f.Severity, f.Description)
				}
			} else {
				t.Logf("%s scanner: found %d findings", tc.name, len(result.Findings))
			}
		})
	}
}

// TestAllViolationsFixture_PANTypeHasMediumSeverity verifies: PAN-TYPE findings
// have MEDIUM severity (defense-in-depth, not direct violation).
func TestAllViolationsFixture_PANTypeHasMediumSeverity(t *testing.T) {
	ctx := context.Background()
	tmpDir := copyAllViolationsFixtures(t)

	s := panscanner.New()
	result, err := s.ScanWithExclusions(ctx, tmpDir, nil)
	if err != nil {
		t.Fatalf("panscanner error: %v", err)
	}

	var panTypeFindings []scanner.Finding
	for _, f := range result.Findings {
		if f.RuleID == "PAN-TYPE" {
			panTypeFindings = append(panTypeFindings, f)
		}
	}

	if len(panTypeFindings) == 0 {
		t.Fatal("expected at least 1 PAN-TYPE finding")
	}

	for _, f := range panTypeFindings {
		if f.Severity != scanner.SeverityMedium {
			t.Errorf("PAN-TYPE finding has severity %s, want MEDIUM: %s", f.Severity, f.Description)
		}
	}
}

// TestAllViolationsFixture_PANKeywordStructFieldOnly verifies: PAN-KEYWORD
// findings come only from struct fields, not function parameters or local variables.
func TestAllViolationsFixture_PANKeywordStructFieldOnly(t *testing.T) {
	ctx := context.Background()
	tmpDir := copyAllViolationsFixtures(t)

	s := panscanner.New()
	result, err := s.ScanWithExclusions(ctx, tmpDir, nil)
	if err != nil {
		t.Fatalf("panscanner error: %v", err)
	}

	for _, f := range result.Findings {
		if f.RuleID != "PAN-KEYWORD" {
			continue
		}
		desc := strings.ToLower(f.Description)
		// PAN-KEYWORD should describe struct fields, not parameters or local variables.
		if strings.Contains(desc, "parameter") || strings.Contains(desc, "variable") {
			t.Errorf("PAN-KEYWORD finding references parameter/variable (violation): %s", f.Description)
		}
	}
}

// TestAllViolationsFixture_JSONCParsing verifies R11-01: secretscanner correctly
// parses all_violations.json containing JSONC comments without error.
func TestAllViolationsFixture_JSONCParsing(t *testing.T) {
	ctx := context.Background()
	tmpDir := copyAllViolationsFixtures(t)

	s := secretscanner.New()
	result, err := s.ScanWithExclusions(ctx, tmpDir, nil)
	if err != nil {
		t.Fatalf("secretscanner error: %v", err)
	}

	// Verify at least one finding came from the.json file.
	var jsonFindings int
	for _, f := range result.Findings {
		if strings.HasSuffix(f.FilePath, ".json") {
			jsonFindings++
		}
	}

	if jsonFindings == 0 {
		t.Error("secretscanner found no findings in .json file (JSONC parsing may have failed)")
		t.Logf("all findings: %+v", result.Findings)
	}
}

// TestAllViolationsFixture_CSPMissingHTMLHigh verifies: CSP-MISSING on
// HTML-serving handlers (template.Execute) has HIGH severity.
func TestAllViolationsFixture_CSPMissingHTMLHigh(t *testing.T) {
	ctx := context.Background()
	tmpDir := copyAllViolationsFixtures(t)

	s := scriptscanner.New()
	result, err := s.ScanWithExclusions(ctx, tmpDir, nil)
	if err != nil {
		t.Fatalf("scriptscanner error: %v", err)
	}

	var cspMissingFindings []scanner.Finding
	for _, f := range result.Findings {
		if f.RuleID == "CSP-MISSING" {
			cspMissingFindings = append(cspMissingFindings, f)
		}
	}

	if len(cspMissingFindings) == 0 {
		t.Fatal("expected at least 1 CSP-MISSING finding")
	}

	// CSP-MISSING with template.Execute (responseHTML) should have HIGH severity.
	hasHigh := false
	for _, f := range cspMissingFindings {
		if f.Severity == scanner.SeverityHigh {
			hasHigh = true
			break
		}
	}

	if !hasHigh {
		t.Errorf("CSP-MISSING findings should include HIGH severity for HTML-serving handler; got: %v",
			formatFindings(cspMissingFindings))
	}
}

// TestAllViolationsFixture_AllRuleCategories runs a comprehensive check that
// findings span all expected rule ID categories across all 9 scanners.
func TestAllViolationsFixture_AllRuleCategories(t *testing.T) {
	ctx := context.Background()
	tmpDir := copyAllViolationsFixtures(t)

	// Expected rule ID prefixes that must appear in the combined findings.
	expectedPrefixes := []string{
		"PAN-",    // panscanner
		"CRYPTO-", // cryptoscanner
		"TLS-",    // tlsscanner
		"ERR-",    // errorscanner
		"SEC-",    // secretscanner
		"AUTH-",   // authscanner
		"AUDIT-",  // auditscanner
		"RET-",    // retentionscanner
		"CSP-",    // scriptscanner (Go handlers)
		"SRI-",    // scriptscanner (HTML)
		"NONCE-",  // scriptscanner (HTML)
	}

	type scannerWithExclusions interface {
		ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error)
	}

	allScanners := []scannerWithExclusions{
		panscanner.New(),
		cryptoscanner.New(),
		tlsscanner.New(),
		errorscanner.New(),
		secretscanner.New(),
		authscanner.New(),
		auditscanner.New(),
		retentionscanner.New(),
		scriptscanner.New(),
	}

	// Collect all findings from all scanners.
	var allFindings []scanner.Finding
	for _, s := range allScanners {
		result, err := s.ScanWithExclusions(ctx, tmpDir, nil)
		if err != nil {
			t.Fatalf("scanner error: %v", err)
		}
		allFindings = append(allFindings, result.Findings...)
	}

	// Build a set of rule ID prefixes found.
	foundPrefixes := make(map[string]bool)
	for _, f := range allFindings {
		for _, prefix := range expectedPrefixes {
			if strings.HasPrefix(f.RuleID, prefix) {
				foundPrefixes[prefix] = true
			}
		}
	}

	// Check all expected prefixes are present.
	for _, prefix := range expectedPrefixes {
		if !foundPrefixes[prefix] {
			t.Errorf("no findings with rule ID prefix %q found", prefix)
		}
	}

	t.Logf("total findings across all scanners: %d", len(allFindings))
	t.Logf("rule categories covered: %d/%d", len(foundPrefixes), len(expectedPrefixes))
}

// --- helpers ---

// copyAllViolationsFixtures copies all_violations.* fixtures from testdata/
// to a temp directory (bypassing DefaultExcludeDirs "testdata" exclusion).
func copyAllViolationsFixtures(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	fixtureDir := filepath.Join("..", "..", "testdata")

	fixtures := []string{
		"all_violations.go",
		"all_violations.html",
		"all_violations.env",
		"all_violations.json",
		"all_violations.yaml",
	}

	for _, f := range fixtures {
		src := filepath.Join(fixtureDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("failed to read fixture %s: %v", f, err)
		}
		dst := filepath.Join(tmpDir, f)
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("failed to write fixture %s: %v", f, err)
		}
	}

	return tmpDir
}

// formatFindings returns a string description of findings for error messages.
func formatFindings(findings []scanner.Finding) string {
	var parts []string
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("%s:%s@%s:%d", f.RuleID, f.Severity, filepath.Base(f.FilePath), f.Line))
	}
	return strings.Join(parts, ", ")
}
