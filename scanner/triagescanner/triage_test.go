package triagescanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestTriageEngine_CachesFileParsing(t *testing.T) {
	t.Parallel()
	// Create a temp Go file.
	dir := t.TempDir()
	goFile := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(goFile, []byte(`package main

import "fmt"

func handler() {
	fmt.Println("hello")
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	findings := []scanner.Finding{
		{RuleID: "AUDIT-NO-LOG", FilePath: "handler.go", Line: 5, Description: "No audit log"},
		{RuleID: "AUDIT-NO-LOG", FilePath: "handler.go", Line: 6, Description: "No audit log 2"},
	}

	result, err := engine.Triage(context.Background(), dir, findings)
	if err != nil {
		t.Fatal(err)
	}

	// Both findings reference the same file — cache should have only 1 entry.
	if len(engine.cache) != 1 {
		t.Errorf("expected cache len 1, got %d", len(engine.cache))
	}

	// Both should have a primary source link and parsed imports.
	for i, ef := range result.Findings {
		if len(ef.Context.Sources) == 0 {
			t.Errorf("finding[%d]: expected at least one Source link, got 0", i)
		} else {
			src := ef.Context.Sources[0]
			if src.URI == "" {
				t.Errorf("finding[%d]: Source[0].URI empty", i)
			}
			if src.StartLine <= 0 || src.EndLine < src.StartLine {
				t.Errorf("finding[%d]: Source[0] line range invalid: start=%d end=%d", i, src.StartLine, src.EndLine)
			}
		}
		if len(ef.Context.Imports) == 0 {
			t.Errorf("finding[%d]: expected imports, got empty", i)
		}
	}
}

func TestTriageEngine_NonGoFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("DB_HOST=localhost\nDB_PASS=secret123\nDB_PORT=5432\n"), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	findings := []scanner.Finding{
		{RuleID: "SECRET-HARDCODED", FilePath: ".env", Line: 2, Description: "Hardcoded password"},
	}

	result, err := engine.Triage(context.Background(), dir, findings)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}

	ef := result.Findings[0]
	if len(ef.Context.Sources) == 0 {
		t.Error("expected source link for .env file, got 0")
	} else if ef.Context.Sources[0].URI == "" {
		t.Error("expected non-empty URI for .env source link")
	}

	// Non-Go file should have no imports.
	if len(ef.Context.Imports) != 0 {
		t.Errorf("expected no imports for .env file, got: %v", ef.Context.Imports)
	}
}

func TestTriageEngine_Metadata(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	goFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(goFile, []byte("package main\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("KEY=val\n"), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	findings := []scanner.Finding{
		{RuleID: "TEST-01", FilePath: "main.go", Line: 1},
		{RuleID: "TEST-02", FilePath: ".env", Line: 1},
	}

	result, err := engine.Triage(context.Background(), dir, findings)
	if err != nil {
		t.Fatal(err)
	}

	if result.Metadata.FindingsTotal != 2 {
		t.Errorf("FindingsTotal: want 2, got %d", result.Metadata.FindingsTotal)
	}
	if result.Metadata.FindingsTriaged != 2 {
		t.Errorf("FindingsTriaged: want 2, got %d", result.Metadata.FindingsTriaged)
	}
	// FilesAnalyzed counts the file cache populated during triage. After
	// we no longer read non-Go files for source embedding, so only
	// the.go file is parsed and cached; the.env finding emits a
	// ResourceLink without touching disk.
	if result.Metadata.FilesAnalyzed != 1 {
		t.Errorf("FilesAnalyzed: want 1 (Go file only after), got %d", result.Metadata.FilesAnalyzed)
	}
	if result.Metadata.DurationMS < 0 {
		t.Errorf("DurationMS should be >= 0, got %d", result.Metadata.DurationMS)
	}
}

func TestTriageEngine_HintGeneration(t *testing.T) {
	t.Parallel()
	engine := NewTriageEngine()

	tests := []struct {
		ruleID string
		want   string
	}{
		{"AUDIT-NO-LOG", "No logging found in handler body"},
		{"AUDIT-UNSTRUCTURED", "Unstructured logging"},
		{"CSP-MISSING", "No CSP header set in handler"},
		{"CSP-UNSAFE-INLINE", "CSP allows unsafe-inline"},
		{"CSP-UNSAFE-EVAL", "CSP allows unsafe-eval"},
		{"AUTH-MISSING-MFA", "No MFA middleware on route"},
		{"SECRET-HARDCODED", "Possible secret in config"},
		{"SECRET-ENV-LEAK", "Possible secret in config"},
		{"CRYPTO-HARDCODED-KEY", "Hardcoded crypto key detected"},
		{"UNKNOWN-RULE", "Review surrounding code and imports"},
	}

	for _, tc := range tests {
		f := scanner.Finding{RuleID: tc.ruleID}
		got := engine.generateHint(f)
		if got == "" {
			t.Errorf("generateHint(%q): got empty hint", tc.ruleID)
			continue
		}
		// Check that the hint contains the expected substring.
		if !containsSubstring(got, tc.want) {
			t.Errorf("generateHint(%q) = %q, want substring %q", tc.ruleID, got, tc.want)
		}
	}
}

func TestTriageEngine_MissingFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	engine := NewTriageEngine()
	findings := []scanner.Finding{
		{RuleID: "TEST-01", FilePath: "nonexistent.go", Line: 1},
	}

	result, err := engine.Triage(context.Background(), dir, findings)
	if err != nil {
		t.Fatal(err)
	}

	// Should still return a result. The Source link is built unconditionally
	// (it's just a URI hint, no file read), so its presence does NOT depend
	// on whether the file exists on disk.
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	// Imports / package decls should be empty because parsing failed.
	if len(result.Findings[0].Context.Imports) != 0 {
		t.Errorf("expected empty imports for missing file, got: %v", result.Findings[0].Context.Imports)
	}
}

func TestTriageEngine_FileLocationClassified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	testDir := filepath.Join(dir, "test")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatal(err)
	}
	testFile := filepath.Join(testDir, "handler_test.go")
	if err := os.WriteFile(testFile, []byte("package test\nfunc TestFoo() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	findings := []scanner.Finding{
		{RuleID: "TEST-01", FilePath: "test/handler_test.go", Line: 1},
	}

	result, err := engine.Triage(context.Background(), dir, findings)
	if err != nil {
		t.Fatal(err)
	}

	if result.Findings[0].Context.FileLocation != "test directory" {
		t.Errorf("FileLocation: want 'test directory', got %q", result.Findings[0].Context.FileLocation)
	}
}

// containsSubstring is a helper to check if s contains substr.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
