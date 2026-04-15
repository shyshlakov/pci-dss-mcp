package panscanner_test

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
)

// countViolationComments counts lines starting with "// VIOLATION:" or
// "# VIOLATION:" in a file.
func countViolationComments(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "// VIOLATION:") || strings.HasPrefix(line, "# VIOLATION:") {
			count++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return count
}

// copyFile copies a file from src to dst.
func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// projectRoot returns the project root directory by walking up from the
// test working directory until go.mod is found.
func projectRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod in any parent directory")
		}
		dir = parent
	}
}

func TestPANViolationsFixture(t *testing.T) {
	root := projectRoot(t)
	fixtureGo := filepath.Join(root, "testdata", "pan_violations.go")
	fixtureEnv := filepath.Join(root, "testdata", ".env")

	// Verify fixtures exist.
	if _, err := os.Stat(fixtureGo); err != nil {
		t.Fatalf("fixture %s not found: %v", fixtureGo, err)
	}
	if _, err := os.Stat(fixtureEnv); err != nil {
		t.Fatalf("fixture %s not found: %v", fixtureEnv, err)
	}

	// Count expected violations from comments.
	goViolations := countViolationComments(t, fixtureGo)
	envViolations := countViolationComments(t, fixtureEnv)
	totalExpected := goViolations + envViolations

	t.Logf("Expected violations: %d Go + %d env = %d total", goViolations, envViolations, totalExpected)

	// Copy fixtures to a temp directory (because DefaultExcludeDirs skips "testdata/").
	tmpDir := t.TempDir()
	copyFile(t, fixtureGo, filepath.Join(tmpDir, "pan_violations.go"))
	copyFile(t, fixtureEnv, filepath.Join(tmpDir, ".env"))

	// Scan using ScanWithExclusions with empty excludes to scan everything.
	s := panscanner.New()
	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions failed: %v", err)
	}

	t.Logf("Actual findings: %d", len(result.Findings))
	for i, f := range result.Findings {
		t.Logf("  [%d] %s %s: %s (line %d)", i+1, f.Severity, f.RuleID, f.Description, f.Line)
	}

	if len(result.Findings) < totalExpected {
		t.Errorf("Expected at least %d findings (from violation comments), got %d", totalExpected, len(result.Findings))
	}

	// Verify specific rule types are present.
	ruleIDs := make(map[string]int)
	severities := make(map[string]int)
	for _, f := range result.Findings {
		ruleIDs[f.RuleID]++
		severities[string(f.Severity)]++
	}

	if ruleIDs["PAN-KEYWORD"] == 0 {
		t.Error("Expected PAN-KEYWORD findings")
	}
	if ruleIDs["PAN-LITERAL"] == 0 {
		t.Error("Expected PAN-LITERAL findings")
	}
	if ruleIDs["PAN-TYPE"] == 0 {
		t.Error("Expected PAN-TYPE findings")
	}
	if ruleIDs["PAN-ZEROING"] == 0 {
		t.Error("Expected PAN-ZEROING findings")
	}
	if ruleIDs["PAN-LOGGER"] == 0 {
		t.Error("Expected PAN-LOGGER findings")
	}

	// Verify severity distribution.
	if severities["CRITICAL"] == 0 {
		t.Error("Expected at least one CRITICAL finding")
	}
	if severities["HIGH"] == 0 {
		t.Error("Expected at least one HIGH finding")
	}
	if severities["MEDIUM"] == 0 {
		t.Error("Expected at least one MEDIUM finding")
	}
}

func TestPANViolationsEnvFixture(t *testing.T) {
	root := projectRoot(t)
	fixtureEnv := filepath.Join(root, "testdata", ".env")

	if _, err := os.Stat(fixtureEnv); err != nil {
		t.Fatalf("fixture %s not found: %v", fixtureEnv, err)
	}

	// Copy fixture to a temp directory.
	tmpDir := t.TempDir()
	copyFile(t, fixtureEnv, filepath.Join(tmpDir, ".env"))

	s := panscanner.New()
	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions failed: %v", err)
	}

	// Expect at least 4 PAN-LITERAL findings from the.env file (4 valid card numbers).
	panLiteralCount := 0
	for _, f := range result.Findings {
		if f.RuleID == "PAN-LITERAL" {
			panLiteralCount++
		}
	}
	if panLiteralCount < 4 {
		t.Errorf("Expected at least 4 PAN-LITERAL findings from .env, got %d", panLiteralCount)
		for _, f := range result.Findings {
			t.Logf("  %s %s: %s (line %d)", f.Severity, f.RuleID, f.Description, f.Line)
		}
	}
}

func TestCleanHandlerZeroFindings(t *testing.T) {
	root := projectRoot(t)
	cleanFile := filepath.Join(root, "testdata", "clean_handler.go")

	if _, err := os.Stat(cleanFile); err != nil {
		t.Fatalf("fixture %s not found: %v", cleanFile, err)
	}

	// Copy to temp directory.
	tmpDir := t.TempDir()
	copyFile(t, cleanFile, filepath.Join(tmpDir, "clean_handler.go"))

	s := panscanner.New()
	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions failed: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for clean_handler.go, got %d:", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  %s %s: %s (line %d)", f.Severity, f.RuleID, f.Description, f.Line)
		}
	}
}
