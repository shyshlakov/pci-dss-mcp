package suppression

import (
	"path/filepath"
	"testing"
)

func TestParseIgnoreFile_NotExists(t *testing.T) {
	rules, err := ParseIgnoreFile("/nonexistent/.pci-dss-mcp-ignore")
	if err != nil {
		t.Fatalf("missing file should return nil error, got: %v", err)
	}
	if rules != nil {
		t.Errorf("missing file should return nil rules, got: %v", rules)
	}
}

func TestParseIgnoreFile_VariousRules(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".pci-dss-mcp-ignore", `# This is a comment
config/test.json:*
config/prod.json:15
testdata/**

*.env
`)

	rules, err := ParseIgnoreFile(filepath.Join(dir, ".pci-dss-mcp-ignore"))
	if err != nil {
		t.Fatalf("ParseIgnoreFile error: %v", err)
	}

	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d: %v", len(rules), rules)
	}

	// config/test.json:* -> Pattern="config/test.json", Line=0
	if rules[0].Pattern != "config/test.json" || rules[0].Line != 0 {
		t.Errorf("rule[0] = %+v, want Pattern=config/test.json Line=0", rules[0])
	}
	if rules[0].SourceLine != 2 {
		t.Errorf("rule[0].SourceLine = %d, want 2", rules[0].SourceLine)
	}

	// config/prod.json:15 -> Pattern="config/prod.json", Line=15
	if rules[1].Pattern != "config/prod.json" || rules[1].Line != 15 {
		t.Errorf("rule[1] = %+v, want Pattern=config/prod.json Line=15", rules[1])
	}
	if rules[1].SourceLine != 3 {
		t.Errorf("rule[1].SourceLine = %d, want 3", rules[1].SourceLine)
	}

	// testdata/** -> Pattern="testdata/**", Line=0
	if rules[2].Pattern != "testdata/**" || rules[2].Line != 0 {
		t.Errorf("rule[2] = %+v, want Pattern=testdata/** Line=0", rules[2])
	}

	// *.env -> Pattern="*.env", Line=0
	if rules[3].Pattern != "*.env" || rules[3].Line != 0 {
		t.Errorf("rule[3] = %+v, want Pattern=*.env Line=0", rules[3])
	}
}

func TestParseIgnoreFile_EmptyLines(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".pci-dss-mcp-ignore", `

# comment

testdata/**

`)

	rules, err := ParseIgnoreFile(filepath.Join(dir, ".pci-dss-mcp-ignore"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestMatchesRule_FileWildcard(t *testing.T) {
	rule := IgnoreRule{Pattern: "config/test.json", Line: 0}

	if !MatchesRule(rule, "config/test.json", 1) {
		t.Error("should match config/test.json at any line")
	}
	if !MatchesRule(rule, "config/test.json", 999) {
		t.Error("should match config/test.json at any line")
	}
	if MatchesRule(rule, "config/other.json", 1) {
		t.Error("should NOT match different file")
	}
}

func TestMatchesRule_SpecificLine(t *testing.T) {
	rule := IgnoreRule{Pattern: "config/prod.json", Line: 15}

	if !MatchesRule(rule, "config/prod.json", 15) {
		t.Error("should match config/prod.json at line 15")
	}
	if MatchesRule(rule, "config/prod.json", 20) {
		t.Error("should NOT match config/prod.json at line 20")
	}
}

func TestMatchesRule_DoubleStarGlob(t *testing.T) {
	rule := IgnoreRule{Pattern: "testdata/**", Line: 0}

	if !MatchesRule(rule, "testdata/foo.go", 1) {
		t.Error("should match testdata/foo.go")
	}
	if !MatchesRule(rule, "testdata/sub/bar.go", 1) {
		t.Error("should match testdata/sub/bar.go")
	}
	if MatchesRule(rule, "src/testdata/foo.go", 1) {
		t.Error("should NOT match src/testdata/foo.go (different prefix)")
	}
}

func TestMatchesRule_SimpleGlob(t *testing.T) {
	rule := IgnoreRule{Pattern: "*.env", Line: 0}

	if !MatchesRule(rule, "secrets.env", 1) {
		t.Error("should match secrets.env")
	}
	if !MatchesRule(rule, ".env", 1) {
		t.Error("should match .env")
	}
	if MatchesRule(rule, "config/secrets.env", 1) {
		t.Error("filepath.Match *.env should not match nested paths")
	}
}

func TestParseExcludePackageDirective(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".pci-dss-mcp-ignore", `# test ignore file
exclude-package: internal/card/**
exclude-package: pkg/game/**
exclude-package:cmd/admin-ui/**
testdata/**
`)

	parsed, err := ParseIgnoreFileFull(filepath.Join(dir, ".pci-dss-mcp-ignore"))
	if err != nil {
		t.Fatalf("ParseIgnoreFileFull error: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed = nil")
	}
	if len(parsed.ExcludePackages) != 3 {
		t.Fatalf("ExcludePackages count = %d, want 3", len(parsed.ExcludePackages))
	}
	if parsed.ExcludePackages[0].Pattern != "internal/card/**" {
		t.Errorf("[0] pattern = %q", parsed.ExcludePackages[0].Pattern)
	}
	if parsed.ExcludePackages[0].SourceLine != 2 {
		t.Errorf("[0] SourceLine = %d, want 2", parsed.ExcludePackages[0].SourceLine)
	}
	if parsed.ExcludePackages[1].Pattern != "pkg/game/**" {
		t.Errorf("[1] pattern = %q", parsed.ExcludePackages[1].Pattern)
	}
	if parsed.ExcludePackages[2].Pattern != "cmd/admin-ui/**" {
		t.Errorf("[2] pattern = %q (no-space form)", parsed.ExcludePackages[2].Pattern)
	}
	if len(parsed.Rules) != 1 {
		t.Errorf("Rules count = %d, want 1 (testdata/** only)", len(parsed.Rules))
	}
	if parsed.Rules[0].Pattern != "testdata/**" {
		t.Errorf("legacy rule pattern = %q", parsed.Rules[0].Pattern)
	}
}

func TestParseExcludePackageDirective_EmptyPattern(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".pci-dss-mcp-ignore", `exclude-package:
exclude-package:
exclude-package: internal/card/**
`)

	parsed, err := ParseIgnoreFileFull(filepath.Join(dir, ".pci-dss-mcp-ignore"))
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(parsed.ExcludePackages) != 1 {
		t.Fatalf("expected 1 valid exclude-package (empty patterns skipped), got %d", len(parsed.ExcludePackages))
	}
}

func TestParseIgnoreFile_BackwardsCompat(t *testing.T) {
	// Legacy ParseIgnoreFile must still return only IgnoreRule entries even
	// when exclude-package directives are present, with the original signature
	// preserved for existing scanner/suppression callers.
	dir := t.TempDir()
	writeFile(t, dir, ".pci-dss-mcp-ignore", `exclude-package: internal/card/**
testdata/**
config/test.json:*
`)

	rules, err := ParseIgnoreFile(filepath.Join(dir, ".pci-dss-mcp-ignore"))
	if err != nil {
		t.Fatalf("ParseIgnoreFile error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("legacy rules count = %d, want 2 (exclude-package not surfaced)", len(rules))
	}
	if rules[0].Pattern != "testdata/**" || rules[1].Pattern != "config/test.json" {
		t.Errorf("legacy rules = %+v", rules)
	}
}

func TestMatchesAnyRule(t *testing.T) {
	rules := []IgnoreRule{
		{Pattern: "config/test.json", Line: 0, SourceLine: 1},
		{Pattern: "testdata/**", Line: 0, SourceLine: 2},
	}

	matched, rule := matchesAnyRule(rules, "testdata/foo.go", 5)
	if !matched {
		t.Error("should match testdata/** rule")
	}
	if rule.SourceLine != 2 {
		t.Errorf("matched rule SourceLine = %d, want 2", rule.SourceLine)
	}

	matched, _ = matchesAnyRule(rules, "src/main.go", 1)
	if matched {
		t.Error("src/main.go should not match any rule")
	}
}
