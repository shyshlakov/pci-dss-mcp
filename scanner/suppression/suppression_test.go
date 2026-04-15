package suppression

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// --- Inline suppression tests ---

func TestInlineSuppression_Go(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

var secretKey = "hunter2" // pci-ignore: known false positive
var anotherKey = "secret123"
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "main.go"), Line: 3, RuleID: "CRYPTO-HARDCODED-KEY"},
		{FilePath: filepath.Join(dir, "main.go"), Line: 4, RuleID: "CRYPTO-HARDCODED-KEY"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("finding on line 3 should be suppressed (has pci-ignore comment)")
	}
	if results[0].SuppressionReason != "known false positive" {
		t.Errorf("reason = %q, want %q", results[0].SuppressionReason, "known false positive")
	}
	if results[0].SuppressionSource != "inline comment" {
		t.Errorf("source = %q, want %q", results[0].SuppressionSource, "inline comment")
	}
	if results[1].Suppressed {
		t.Error("finding on line 4 should NOT be suppressed")
	}
}

func TestInlineSuppression_Go_NoSpace(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

var secretKey = "hunter2" //pci-ignore:reason
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "main.go"), Line: 3, RuleID: "CRYPTO-HARDCODED-KEY"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("should be suppressed with //pci-ignore: (no space)")
	}
	if results[0].SuppressionReason != "reason" {
		t.Errorf("reason = %q, want %q", results[0].SuppressionReason, "reason")
	}
}

func TestInlineSuppression_Go_EmptyReason(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

var secretKey = "hunter2" // pci-ignore:
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "main.go"), Line: 3, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("empty reason should still suppress")
	}
	if results[0].SuppressionReason != "" {
		t.Errorf("reason = %q, want empty", results[0].SuppressionReason)
	}
}

func TestInlineSuppression_Yaml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", `password: secret123 # pci-ignore: test environment
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config.yaml"), Line: 1, RuleID: "SEC-YAML"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("YAML pci-ignore should suppress")
	}
	if results[0].SuppressionReason != "test environment" {
		t.Errorf("reason = %q, want %q", results[0].SuppressionReason, "test environment")
	}
}

func TestInlineSuppression_Yml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yml", `api_key: test123 # pci-ignore: dev only
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config.yml"), Line: 1, RuleID: "SEC-YAML"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error(".yml pci-ignore should suppress")
	}
}

func TestInlineSuppression_Env(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".env", `SECRET=value123 # pci-ignore: dev only
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, ".env"), Line: 1, RuleID: "SEC-ENV"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error(".env pci-ignore should suppress")
	}
}

func TestInlineSuppression_Toml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.toml", `secret = "value" # pci-ignore: config override
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config.toml"), Line: 1, RuleID: "SEC-TOML"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error(".toml pci-ignore should suppress")
	}
}

func TestInlineSuppression_HTML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "page.html", `<script src="http://cdn.example.com/lib.js"></script> <!-- pci-ignore: template exception -->
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "page.html"), Line: 1, RuleID: "SCRIPT-01"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("HTML pci-ignore should suppress")
	}
	if results[0].SuppressionReason != "template exception" {
		t.Errorf("reason = %q, want %q", results[0].SuppressionReason, "template exception")
	}
}

func TestInlineSuppression_Tmpl(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "page.tmpl", `<script src="x"></script> <!-- pci-ignore: reason -->
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "page.tmpl"), Line: 1, RuleID: "SCRIPT-01"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error(".tmpl pci-ignore should suppress")
	}
}

func TestInlineSuppression_Gohtml(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "page.gohtml", `<script src="x"></script> <!-- pci-ignore: reason -->
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "page.gohtml"), Line: 1, RuleID: "SCRIPT-01"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error(".gohtml pci-ignore should suppress")
	}
}

func TestInlineSuppression_JSON_NoSupport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.json", `{"key": "value", "comment": "// pci-ignore: reason"}
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config.json"), Line: 1, RuleID: "SEC-JSON"},
	}

	results := ApplySuppression(findings, dir)

	if results[0].Suppressed {
		t.Error("JSON files should NOT support inline pci-ignore (no comment syntax)")
	}
}

func TestInlineSuppression_WrongLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

var secretKey = "hunter2"
// pci-ignore: this is on line 4, not line 3
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "main.go"), Line: 3, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, dir)

	if results[0].Suppressed {
		t.Error("pci-ignore on different line should NOT suppress")
	}
}

func TestInlineSuppression_FileNotFound(t *testing.T) {
	findings := []scanner.Finding{
		{FilePath: "/nonexistent/file.go", Line: 1, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, "/nonexistent")

	if results[0].Suppressed {
		t.Error("missing file should not suppress")
	}
}

func TestInlineSuppression_MultipleFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "main.go", `package main

var key1 = "secret1" // pci-ignore: known
var key2 = "secret2"
var key3 = "secret3" // pci-ignore: also known
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "main.go"), Line: 3, RuleID: "T1"},
		{FilePath: filepath.Join(dir, "main.go"), Line: 4, RuleID: "T2"},
		{FilePath: filepath.Join(dir, "main.go"), Line: 5, RuleID: "T3"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("line 3 should be suppressed")
	}
	if results[1].Suppressed {
		t.Error("line 4 should NOT be suppressed")
	}
	if !results[2].Suppressed {
		t.Error("line 5 should be suppressed")
	}
}

// --- Ignore file integration tests ---

func TestIgnoreFile_Integration_GlobSuppression(t *testing.T) {
	dir := t.TempDir()

	// Create.pci-dss-mcp-ignore with glob rule.
	writeFile(t, dir, ".pci-dss-mcp-ignore", `# Suppress all testdata
testdata/**
`)

	// Create a file in testdata/.
	writeFile(t, dir, "testdata/foo.go", `package testdata
var key = "secret"
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "testdata/foo.go"), Line: 2, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("finding in testdata/ should be suppressed by testdata/** rule")
	}
	if results[0].SuppressionSource != ".pci-dss-mcp-ignore:2" {
		t.Errorf("source = %q, want %q", results[0].SuppressionSource, ".pci-dss-mcp-ignore:2")
	}
}

func TestIgnoreFile_Integration_FileWildcard(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, ".pci-dss-mcp-ignore", `config/test.json:*
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config/test.json"), Line: 5, RuleID: "TEST"},
		{FilePath: filepath.Join(dir, "config/test.json"), Line: 20, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("line 5 should be suppressed by file:* rule")
	}
	if !results[1].Suppressed {
		t.Error("line 20 should be suppressed by file:* rule")
	}
}

func TestIgnoreFile_Integration_SpecificLine(t *testing.T) {
	dir := t.TempDir()

	writeFile(t, dir, ".pci-dss-mcp-ignore", `config/prod.json:15
`)

	findings := []scanner.Finding{
		{FilePath: filepath.Join(dir, "config/prod.json"), Line: 15, RuleID: "TEST"},
		{FilePath: filepath.Join(dir, "config/prod.json"), Line: 20, RuleID: "TEST"},
	}

	results := ApplySuppression(findings, dir)

	if !results[0].Suppressed {
		t.Error("line 15 should be suppressed")
	}
	if results[1].Suppressed {
		t.Error("line 20 should NOT be suppressed (rule targets line 15)")
	}
}

// --- Package exclusion tests ---

func TestApplyPackageExclusions(t *testing.T) {
	findings := []scanner.Finding{
		{RuleID: "AUTH-MISSING-MFA", FilePath: "internal/card/game.go", Line: 10},
		{RuleID: "PAN-KEYWORD", FilePath: "internal/payment/core.go", Line: 19},
		{RuleID: "CRYPTO-WEAK-HASH", FilePath: "pkg/game/deal.go", Line: 3},
		{RuleID: "ERR-LEAK-FORMAT", FilePath: "internal/card/deck.go", Line: 42},
	}
	rules := []ExcludePackageRule{
		{Pattern: "internal/card/**", SourceLine: 3},
		{Pattern: "pkg/game/**", SourceLine: 4},
	}

	filtered, reports := ApplyPackageExclusions(findings, ".", rules)
	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1", len(filtered))
	}
	if filtered[0].FilePath != "internal/payment/core.go" {
		t.Errorf("surviving finding = %q", filtered[0].FilePath)
	}
	if len(reports) != 2 {
		t.Fatalf("reports len = %d, want 2", len(reports))
	}
	// Reports must come back in the same order as the rules slice.
	if reports[0].Pattern != "internal/card/**" || reports[0].MatchCount != 2 {
		t.Errorf("reports[0] = %+v, want internal/card/** count=2", reports[0])
	}
	if reports[0].SourceLine != 3 {
		t.Errorf("reports[0].SourceLine = %d, want 3", reports[0].SourceLine)
	}
	if reports[1].Pattern != "pkg/game/**" || reports[1].MatchCount != 1 {
		t.Errorf("reports[1] = %+v, want pkg/game/** count=1", reports[1])
	}
}

func TestApplyPackageExclusions_NoRules(t *testing.T) {
	findings := []scanner.Finding{
		{RuleID: "AUTH-MISSING-MFA", FilePath: "internal/card/game.go"},
	}
	filtered, reports := ApplyPackageExclusions(findings, ".", nil)
	if len(filtered) != 1 {
		t.Errorf("filtered len = %d, want 1 (unchanged)", len(filtered))
	}
	if len(reports) != 0 {
		t.Errorf("reports len = %d, want 0", len(reports))
	}
}

func TestApplyPackageExclusions_NoFindings(t *testing.T) {
	rules := []ExcludePackageRule{{Pattern: "internal/card/**", SourceLine: 1}}
	filtered, reports := ApplyPackageExclusions(nil, ".", rules)
	if filtered != nil {
		t.Errorf("filtered = %v, want nil", filtered)
	}
	if reports != nil {
		t.Errorf("reports = %v, want nil", reports)
	}
}

func TestApplyPackageExclusions_NoMatch(t *testing.T) {
	findings := []scanner.Finding{
		{RuleID: "PAN-KEYWORD", FilePath: "internal/payment/core.go", Line: 19},
	}
	rules := []ExcludePackageRule{
		{Pattern: "internal/card/**", SourceLine: 3},
	}

	filtered, reports := ApplyPackageExclusions(findings, ".", rules)
	if len(filtered) != 1 {
		t.Errorf("filtered len = %d, want 1 (no match)", len(filtered))
	}
	if len(reports) != 0 {
		t.Errorf("reports len = %d, want 0 (zero matches → no audit entry)", len(reports))
	}
}

func TestApplyPackageExclusions_AbsolutePaths(t *testing.T) {
	root := "/tmp/proj"
	findings := []scanner.Finding{
		{RuleID: "AUTH-MISSING-MFA", FilePath: "/tmp/proj/internal/card/game.go", Line: 10},
		{RuleID: "PAN-KEYWORD", FilePath: "/tmp/proj/internal/payment/core.go", Line: 19},
	}
	rules := []ExcludePackageRule{
		{Pattern: "internal/card/**", SourceLine: 3},
	}

	filtered, reports := ApplyPackageExclusions(findings, root, rules)
	if len(filtered) != 1 {
		t.Fatalf("filtered len = %d, want 1", len(filtered))
	}
	if filtered[0].FilePath != "/tmp/proj/internal/payment/core.go" {
		t.Errorf("surviving = %q", filtered[0].FilePath)
	}
	if len(reports) != 1 || reports[0].MatchCount != 1 {
		t.Errorf("reports = %+v", reports)
	}
}

// --- helpers ---

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
