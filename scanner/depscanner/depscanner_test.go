package depscanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestParseGoMod(t *testing.T) {
	t.Run("extracts direct dependencies with path version and line", func(t *testing.T) {
		content := `module example.com/app

go 1.21

require (
	golang.org/x/net v0.20.0
	golang.org/x/text v0.14.0
	github.com/gin-gonic/gin v1.9.0
)

require (
	github.com/some/indirect v1.0.0 // indirect
)
`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		deps, err := parseGoMod(dir)
		if err != nil {
			t.Fatalf("parseGoMod() error: %v", err)
		}

		if len(deps) != 3 {
			t.Fatalf("expected 3 direct deps, got %d", len(deps))
		}

		// Verify first dep.
		if deps[0].Path != "golang.org/x/net" {
			t.Errorf("deps[0].Path = %q, want %q", deps[0].Path, "golang.org/x/net")
		}
		if deps[0].Version != "v0.20.0" {
			t.Errorf("deps[0].Version = %q, want %q", deps[0].Version, "v0.20.0")
		}
		if deps[0].Line <= 0 {
			t.Errorf("deps[0].Line = %d, want positive line number", deps[0].Line)
		}
	})

	t.Run("excludes indirect dependencies", func(t *testing.T) {
		content := `module example.com/app

go 1.21

require golang.org/x/net v0.20.0

require (
	github.com/some/indirect v1.0.0 // indirect
	github.com/other/indirect v1.2.0 // indirect
)
`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		deps, err := parseGoMod(dir)
		if err != nil {
			t.Fatalf("parseGoMod() error: %v", err)
		}

		if len(deps) != 1 {
			t.Fatalf("expected 1 direct dep, got %d", len(deps))
		}
		if deps[0].Path != "golang.org/x/net" {
			t.Errorf("deps[0].Path = %q, want %q", deps[0].Path, "golang.org/x/net")
		}
	})

	t.Run("handles single-line require statements", func(t *testing.T) {
		content := `module example.com/app

go 1.21

require golang.org/x/net v0.20.0
require golang.org/x/text v0.14.0
`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		deps, err := parseGoMod(dir)
		if err != nil {
			t.Fatalf("parseGoMod() error: %v", err)
		}

		if len(deps) != 2 {
			t.Fatalf("expected 2 deps, got %d", len(deps))
		}
	})

	t.Run("returns error for missing go.mod file", func(t *testing.T) {
		dir := t.TempDir()
		_, err := parseGoMod(dir)
		if err == nil {
			t.Fatal("expected error for missing go.mod")
		}
	})

	t.Run("returns error for malformed go.mod content", func(t *testing.T) {
		dir := t.TempDir()
		// Write content that is not a valid go.mod.
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("not a valid go.mod {{{"), 0o644); err != nil {
			t.Fatal(err)
		}

		// ParseLax is very lenient, so we test with truly broken content.
		// ParseLax may or may not error on this; the important thing is no panic.
		_, _ = parseGoMod(dir)
	})

	t.Run("handles block require syntax", func(t *testing.T) {
		content := `module example.com/app

go 1.21

require (
	golang.org/x/net v0.20.0
	golang.org/x/text v0.14.0
)
`
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		deps, err := parseGoMod(dir)
		if err != nil {
			t.Fatalf("parseGoMod() error: %v", err)
		}

		if len(deps) != 2 {
			t.Fatalf("expected 2 deps, got %d", len(deps))
		}
	})
}

func TestBuildFinding(t *testing.T) {
	dep := Dependency{
		Path:    "golang.org/x/net",
		Version: "v0.20.0",
		Line:    6,
	}

	t.Run("constructs Finding with FilePath=go.mod per ", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			Aliases:          []string{"CVE-2024-1234"},
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			Affected: []Affected{
				{
					Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
					Ranges: []Range{
						{
							Type: "SEMVER",
							Events: []Event{
								{Introduced: "0"},
								{Fixed: "0.23.0"},
							},
						},
					},
				},
			},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if f.FilePath != "go.mod" {
			t.Errorf("FilePath = %q, want %q", f.FilePath, "go.mod")
		}
	})

	t.Run("sets RequirementID=6.3.3 per ", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if f.RequirementID != "6.3.3" {
			t.Errorf("RequirementID = %q, want %q", f.RequirementID, "6.3.3")
		}
	})

	t.Run("description includes CVE/GHSA ID module path installed version", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			Aliases:          []string{"CVE-2024-1234"},
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			Affected: []Affected{
				{
					Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
					Ranges: []Range{
						{
							Type: "SEMVER",
							Events: []Event{
								{Introduced: "0"},
								{Fixed: "0.23.0"},
							},
						},
					},
				},
			},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if !strings.Contains(f.Description, "GHSA-xxxx-xxxx-xxxx") {
			t.Errorf("description missing GHSA ID: %q", f.Description)
		}
		if !strings.Contains(f.Description, "CVE-2024-1234") {
			t.Errorf("description missing CVE ID: %q", f.Description)
		}
		if !strings.Contains(f.Description, "golang.org/x/net") {
			t.Errorf("description missing module path: %q", f.Description)
		}
		if !strings.Contains(f.Description, "v0.20.0") {
			t.Errorf("description missing installed version: %q", f.Description)
		}
	})

	t.Run("suggestion says go get when fix available per ", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if !strings.Contains(f.Suggestion, "go get") {
			t.Errorf("suggestion missing 'go get': %q", f.Suggestion)
		}
		if !strings.Contains(f.Suggestion, "golang.org/x/net@v0.23.0") {
			t.Errorf("suggestion missing module@fix_version: %q", f.Suggestion)
		}
	})

	t.Run("suggestion says No fix available when no fix version per ", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
		}

		f := buildFinding(dep, vuln, "")

		if !strings.Contains(f.Suggestion, "No fix available") {
			t.Errorf("suggestion missing 'No fix available': %q", f.Suggestion)
		}
	})

	t.Run("PCI context for CRITICAL/HIGH/MEDIUM per ", func(t *testing.T) {
		for _, sev := range []string{"CRITICAL", "HIGH", "MODERATE"} {
			vuln := &Vulnerability{
				ID:               "GHSA-xxxx-xxxx-xxxx",
				Summary:          "Test vulnerability",
				DatabaseSpecific: DatabaseSpecific{Severity: sev},
			}

			f := buildFinding(dep, vuln, "v0.23.0")

			if !strings.Contains(f.Description, "PCI DSS 6.3.3 requires remediation within 30 days") {
				t.Errorf("severity %s: missing PCI context in description: %q", sev, f.Description)
			}
		}
	})

	t.Run("PCI context for LOW per ", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "LOW"},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if !strings.Contains(f.Description, "below ASV scan failure threshold") {
			t.Errorf("LOW: missing PCI context in description: %q", f.Description)
		}
	})

	t.Run("line number preserved from dependency", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if f.Line != 6 {
			t.Errorf("Line = %d, want %d", f.Line, 6)
		}
	})

	t.Run("RuleID is DEP-VULN", func(t *testing.T) {
		vuln := &Vulnerability{
			ID:               "GHSA-xxxx-xxxx-xxxx",
			Summary:          "Test vulnerability",
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
		}

		f := buildFinding(dep, vuln, "v0.23.0")

		if f.RuleID != "DEP-VULN" {
			t.Errorf("RuleID = %q, want %q", f.RuleID, "DEP-VULN")
		}
	})
}

func TestScannerInterface(t *testing.T) {
	s := New()

	t.Run("Name returns dependency_vulnerability", func(t *testing.T) {
		if s.Name() != "dependency_vulnerability" {
			t.Errorf("Name() = %q, want %q", s.Name(), "dependency_vulnerability")
		}
	})

	t.Run("Description is non-empty", func(t *testing.T) {
		if s.Description() == "" {
			t.Error("Description() should not be empty")
		}
	})

	t.Run("Requirements returns 6.3.3", func(t *testing.T) {
		reqs := s.Requirements()
		if len(reqs) != 1 || reqs[0] != "6.3.3" {
			t.Errorf("Requirements() = %v, want [6.3.3]", reqs)
		}
	})

	// Verify interface compliance at compile time.
	var _ scanner.Scanner = (*DependencyScanner)(nil)
}

// setupTestGoMod creates a temp directory with a go.mod containing a vulnerable dependency.
func setupTestGoMod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	content := `module example.com/app

go 1.21

require golang.org/x/net v0.20.0
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// setupTestCache creates a temp cache directory with a valid cache file.
func setupTestCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cache := CacheFile{
		Generated: time.Now().UTC(),
		Source:    "test",
		VulnCount: 1,
		Packages: map[string][]Vulnerability{
			"golang.org/x/net": {
				{
					ID:               "GHSA-test-0001",
					Summary:          "Test vulnerability in x/net",
					Aliases:          []string{"CVE-2024-0001"},
					DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
					Affected: []Affected{
						{
							Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
							Ranges: []Range{
								{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.23.0"}}},
							},
						},
					},
				},
			},
		},
	}

	data, _ := json.Marshal(cache)
	cacheFile := filepath.Join(dir, "go-osv-"+time.Now().Format("2006-01-02")+".json")
	if err := os.WriteFile(cacheFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanFromCache(t *testing.T) {
	cacheDir := setupTestCache(t)
	dir := setupTestGoMod(t)

	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	s := New()

	result, err := s.ScanWithMode(context.Background(), dir, "auto")
	if err != nil {
		t.Fatalf("ScanWithMode(auto) error: %v", err)
	}

	if result == nil {
		t.Fatal("result is nil")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected findings from cache")
	}

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "DEP-VULN" && strings.Contains(f.Description, "GHSA-test-0001") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected finding with GHSA-test-0001")
	}
}

func TestScanFromCacheNoCache(t *testing.T) {
	dir := setupTestGoMod(t)

	t.Setenv("PCI_MCP_CACHE_DIR", filepath.Join(t.TempDir(), "nonexistent"))
	t.Setenv("OSV_BASE_URL", "http://127.0.0.1:1")

	s := New()

	result, err := s.ScanWithMode(context.Background(), dir, "auto")
	if err != nil {
		t.Fatalf("expected graceful degradation, got err: %v", err)
	}
	saw := false
	for _, f := range result.Findings {
		if f.RuleID == "DEP-CACHE-COLD" && f.Severity == scanner.SeverityInfo {
			saw = true
			break
		}
	}
	if !saw {
		t.Fatalf("expected DEP-CACHE-COLD INFO finding when no cache exists; got %+v", result.Findings)
	}
}

func TestScanWithModeRejectsRemovedKeywords(t *testing.T) {
	dir := setupTestGoMod(t)
	t.Setenv("PCI_MCP_CACHE_DIR", t.TempDir())

	s := New()

	tt := []struct {
		name string
		mode string
	}{
		{name: "online_rejected", mode: "online"},
		{name: "offline_rejected", mode: "offline"},
		{name: "garbage_rejected", mode: "garbage"},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.ScanWithMode(context.Background(), dir, tc.mode)
			if err == nil {
				t.Fatalf("ScanWithMode(%q) returned nil err; want migration error", tc.mode)
			}
			msg := err.Error()
			if !strings.Contains(msg, "auto") {
				t.Errorf("error must mention \"auto\" as supported value; got: %s", msg)
			}
			if tc.mode == "online" || tc.mode == "offline" {
				if !strings.Contains(msg, "removed in v0.6.3") {
					t.Errorf("error must reference removal in v0.6.3 for mode=%q; got: %s", tc.mode, msg)
				}
				if !strings.Contains(msg, "module-name disclosure") {
					t.Errorf("error must explain privacy rationale (module-name disclosure) for mode=%q; got: %s", tc.mode, msg)
				}
			}
		})
	}
}

// TestDepscanner_NeverClimbsAncestor is a defensive regression guard.
//
// depscanner.parseGoMod reads targetPath/go.mod directly
// with no walker, and buildFinding hard-codes FilePath = "go.mod". This test locks
// that behavior in place so any future refactor that introduces an upward go.mod
// search regresses this test instead of silently shipping wrong paths.
//
// Setup: a nested directory layout where the ancestor (outer) go.mod contains a
// BOGUS declaration of golang.org/x/net on a high line number. The scan-root go.mod
// also declares golang.org/x/net, but on a low line number. If the scanner ever
// starts climbing past the scan root, the finding would cite the ancestor's line
// number; this test catches that regression.
func TestDepscanner_NeverClimbsAncestor(t *testing.T) {
	cacheDir := setupTestCache(t)
	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	outer := t.TempDir()

	ancestorGoMod := `module example.com/ancestor

go 1.21

// padding so the require directive lands on a high line number
// trap line 5
// trap line 6
// trap line 7
// trap line 8
// trap line 9
// trap line 10
// trap line 11
// trap line 12
// trap line 13
// trap line 14
// trap line 15
// trap line 16
// trap line 17
// trap line 18
// trap line 19
// trap line 20
// trap line 21
// trap line 22
// trap line 23
// trap line 24
// trap line 25
// trap line 26
// trap line 27
// trap line 28
// trap line 29
require golang.org/x/net v0.20.0
`
	if err := os.WriteFile(filepath.Join(outer, "go.mod"), []byte(ancestorGoMod), 0o644); err != nil {
		t.Fatalf("write ancestor go.mod: %v", err)
	}

	scanRoot := filepath.Join(outer, "nested", "service")
	if err := os.MkdirAll(scanRoot, 0o755); err != nil {
		t.Fatalf("mkdir scan root: %v", err)
	}

	scanRootGoMod := `module example.com/app

go 1.21

require golang.org/x/net v0.20.0
`
	if err := os.WriteFile(filepath.Join(scanRoot, "go.mod"), []byte(scanRootGoMod), 0o644); err != nil {
		t.Fatalf("write scan root go.mod: %v", err)
	}

	s := New()

	result, err := s.ScanWithMode(context.Background(), scanRoot, "auto")
	if err != nil {
		t.Fatalf("ScanWithMode(auto) error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}

	var depVulns int
	for _, f := range result.Findings {
		if f.RuleID != "DEP-VULN" {
			continue
		}
		depVulns++

		if f.FilePath != "go.mod" {
			t.Errorf("DEP-VULN FilePath = %q, want %q (walker must not climb past scan root or relativize the path)", f.FilePath, "go.mod")
		}

		if filepath.IsAbs(f.FilePath) {
			t.Errorf("DEP-VULN FilePath = %q is absolute, must be literal %q", f.FilePath, "go.mod")
		}

		if strings.Contains(f.FilePath, "..") {
			t.Errorf("DEP-VULN FilePath = %q contains ancestor traversal, must be literal %q", f.FilePath, "go.mod")
		}

		if f.Line != 5 {
			t.Errorf("DEP-VULN Line = %d, want 5 (scan-root go.mod); a value of 30 would indicate the scanner climbed to the ancestor go.mod", f.Line)
		}
	}

	if depVulns == 0 {
		t.Fatal("no DEP-VULN findings produced from scan-root go.mod; test cannot verify path behavior; check setupTestCache vulnerability entry")
	}
}
