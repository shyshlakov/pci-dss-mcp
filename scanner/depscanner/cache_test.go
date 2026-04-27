package depscanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestResolveCachePath(t *testing.T) {
	t.Run("returns PCI_MCP_CACHE_DIR env value when set", func(t *testing.T) {
		t.Setenv("PCI_MCP_CACHE_DIR", "/custom/cache/path")

		result, err := resolveCachePath()
		if err != nil {
			t.Fatalf("resolveCachePath() err = %v", err)
		}
		if result != "/custom/cache/path" {
			t.Errorf("resolveCachePath() = %q, want /custom/cache/path", result)
		}
	})

	t.Run("returns ~/.pci-dss-mcp/vuln-cache/ when env not set", func(t *testing.T) {
		t.Setenv("PCI_MCP_CACHE_DIR", "")

		result, err := resolveCachePath()
		if err != nil {
			t.Fatalf("resolveCachePath() err = %v", err)
		}
		if !strings.HasSuffix(result, filepath.Join(".pci-dss-mcp", "vuln-cache")) {
			t.Errorf("resolveCachePath() = %q, should end with .pci-dss-mcp/vuln-cache", result)
		}
		if result == "" || result[0] != '/' {
			t.Errorf("resolveCachePath() = %q, expected absolute path", result)
		}
	})
}

func TestResolveCachePathChain(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "explicit_env_var_wins",
			run: func(t *testing.T) {
				t.Setenv("PCI_MCP_CACHE_DIR", "/tmp/x")
				t.Setenv("XDG_CACHE_HOME", "/abs/xdg")
				t.Setenv("HOME", "/abs/home")

				got, err := resolveCachePath()
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if got != "/tmp/x" {
					t.Errorf("got %q, want /tmp/x", got)
				}
			},
		},
		{
			name: "xdg_absolute_used",
			run: func(t *testing.T) {
				t.Setenv("PCI_MCP_CACHE_DIR", "")
				t.Setenv("XDG_CACHE_HOME", "/abs/path")
				t.Setenv("HOME", "/abs/home")

				got, err := resolveCachePath()
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				want := filepath.Join("/abs/path", "pci-dss-mcp", "vuln-cache")
				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			},
		},
		{
			name: "xdg_relative_skipped",
			run: func(t *testing.T) {
				t.Setenv("PCI_MCP_CACHE_DIR", "")
				t.Setenv("XDG_CACHE_HOME", "relative/path")
				t.Setenv("HOME", "/h")

				got, err := resolveCachePath()
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				want := filepath.Join("/h", defaultCacheDir)
				if got != want {
					t.Errorf("got %q, want %q (relative XDG must be skipped)", got, want)
				}
			},
		},
		{
			name: "home_default",
			run: func(t *testing.T) {
				t.Setenv("PCI_MCP_CACHE_DIR", "")
				t.Setenv("XDG_CACHE_HOME", "")
				t.Setenv("HOME", "/h")

				got, err := resolveCachePath()
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				want := filepath.Join("/h", defaultCacheDir)
				if got != want {
					t.Errorf("got %q, want %q", got, want)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}

func TestLatestCacheFile(t *testing.T) {
	t.Run("finds most recent go-osv-YYYY-MM-DD.json in directory", func(t *testing.T) {
		dir := t.TempDir()

		// Create several cache files with different dates.
		for _, name := range []string{
			"go-osv-2024-01-01.json",
			"go-osv-2024-03-15.json",
			"go-osv-2024-02-10.json",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		path, date, err := latestCacheFile(dir)
		if err != nil {
			t.Fatalf("latestCacheFile() error: %v", err)
		}

		expectedPath := filepath.Join(dir, "go-osv-2024-03-15.json")
		if path != expectedPath {
			t.Errorf("path = %q, want %q", path, expectedPath)
		}

		expectedDate := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
		if !date.Equal(expectedDate) {
			t.Errorf("date = %v, want %v", date, expectedDate)
		}
	})

	t.Run("returns error when no cache files exist", func(t *testing.T) {
		dir := t.TempDir()

		_, _, err := latestCacheFile(dir)
		if err == nil {
			t.Fatal("expected error for empty directory")
		}
	})

	t.Run("ignores non-matching files in cache directory", func(t *testing.T) {
		dir := t.TempDir()

		// Create non-matching files.
		for _, name := range []string{
			"other-file.json",
			"go-osv-bad-date.json",
			"readme.txt",
		} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		// Create one valid cache file.
		if err := os.WriteFile(filepath.Join(dir, "go-osv-2024-06-01.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		path, _, err := latestCacheFile(dir)
		if err != nil {
			t.Fatalf("latestCacheFile() error: %v", err)
		}

		if !strings.Contains(path, "go-osv-2024-06-01.json") {
			t.Errorf("path = %q, should contain go-osv-2024-06-01.json", path)
		}
	})

	t.Run("returns error when directory does not exist", func(t *testing.T) {
		_, _, err := latestCacheFile("/nonexistent/path/that/does/not/exist")
		if err == nil {
			t.Fatal("expected error for nonexistent directory")
		}
	})
}

func TestLoadCache(t *testing.T) {
	t.Run("reads and unmarshals CacheFile JSON", func(t *testing.T) {
		cache := CacheFile{
			Generated: time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
			Source:    "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip",
			VulnCount: 100,
			Packages: map[string][]Vulnerability{
				"golang.org/x/net": {
					{ID: "GHSA-1234", Summary: "test vuln"},
				},
			},
		}

		dir := t.TempDir()
		data, _ := json.Marshal(cache)
		path := filepath.Join(dir, "test-cache.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}

		loaded, err := loadCache(path)
		if err != nil {
			t.Fatalf("loadCache() error: %v", err)
		}

		if loaded.VulnCount != 100 {
			t.Errorf("VulnCount = %d, want 100", loaded.VulnCount)
		}
		if loaded.Source != cache.Source {
			t.Errorf("Source = %q, want %q", loaded.Source, cache.Source)
		}
		vulns, ok := loaded.Packages["golang.org/x/net"]
		if !ok || len(vulns) != 1 {
			t.Fatalf("Packages[golang.org/x/net] missing or wrong length")
		}
		if vulns[0].ID != "GHSA-1234" {
			t.Errorf("vuln ID = %q, want GHSA-1234", vulns[0].ID)
		}
	})

	t.Run("returns error for corrupt JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "corrupt.json")
		if err := os.WriteFile(path, []byte("not valid json {{{"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := loadCache(path)
		if err == nil {
			t.Fatal("expected error for corrupt JSON")
		}
	})

	t.Run("returns error for missing file", func(t *testing.T) {
		_, err := loadCache("/nonexistent/file.json")
		if err == nil {
			t.Fatal("expected error for missing file")
		}
	})
}

func TestCheckStaleness(t *testing.T) {
	tests := []struct {
		daysAgo  int
		expected CacheStaleness
	}{
		{0, CacheFresh},
		{1, CacheFresh},
		{6, CacheFresh},
		{7, CacheStale},
		{10, CacheStale},
		{14, CacheStale},
		{15, CacheCritical},
		{30, CacheCritical},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d_days_ago", tt.daysAgo), func(t *testing.T) {
			cacheDate := time.Now().UTC().AddDate(0, 0, -tt.daysAgo)
			result := checkStaleness(cacheDate)
			if result != tt.expected {
				t.Errorf("checkStaleness(%d days ago) = %d, want %d", tt.daysAgo, result, tt.expected)
			}
		})
	}
}

func TestStalenessWarning(t *testing.T) {
	t.Run("returns empty string for Fresh", func(t *testing.T) {
		result := stalenessWarning(CacheFresh, time.Now())
		if result != "" {
			t.Errorf("stalenessWarning(Fresh) = %q, want empty", result)
		}
	})

	t.Run("returns MEDIUM warning text for Stale per ", func(t *testing.T) {
		cacheDate := time.Now().UTC().AddDate(0, 0, -10)
		result := stalenessWarning(CacheStale, cacheDate)
		if !strings.Contains(result, "Run update_vulnerability_db") {
			t.Errorf("Stale warning missing 'Run update_vulnerability_db': %q", result)
		}
		if !strings.Contains(result, "10") {
			t.Errorf("Stale warning missing day count: %q", result)
		}
	})

	t.Run("returns HIGH warning text for Critical per ", func(t *testing.T) {
		cacheDate := time.Now().UTC().AddDate(0, 0, -20)
		result := stalenessWarning(CacheCritical, cacheDate)
		if !strings.Contains(result, "PCI DSS 6.3.3 requires timely detection") {
			t.Errorf("Critical warning missing PCI DSS text: %q", result)
		}
		if !strings.Contains(result, "Update immediately") {
			t.Errorf("Critical warning missing 'Update immediately': %q", result)
		}
	})
}

func TestCacheAgeMessage(t *testing.T) {
	t.Run("returns formatted message per ", func(t *testing.T) {
		cacheDate := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
		result := cacheAgeMessage(cacheDate)

		if !strings.Contains(result, "2024-06-15") {
			t.Errorf("missing date in message: %q", result)
		}
		if !strings.Contains(result, "days ago") {
			t.Errorf("missing 'days ago' in message: %q", result)
		}
		if !strings.Contains(result, "Offline scan using cache from") {
			t.Errorf("missing prefix in message: %q", result)
		}
	})
}

func TestLookupCache(t *testing.T) {
	cache := &CacheFile{
		Packages: map[string][]Vulnerability{
			"golang.org/x/net": {
				{
					ID:      "GHSA-1234",
					Summary: "vuln in x/net",
					Affected: []Affected{
						{
							Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
							Ranges: []Range{
								{
									Type:   "SEMVER",
									Events: []Event{{Introduced: "0"}, {Fixed: "0.23.0"}},
								},
							},
						},
					},
				},
			},
			"golang.org/x/net/http2": {
				{
					ID:      "GHSA-5678",
					Summary: "vuln in x/net/http2 subpackage",
					Affected: []Affected{
						{
							Package: AffectedPackage{Name: "golang.org/x/net/http2", Ecosystem: "Go"},
							Ranges: []Range{
								{
									Type:   "SEMVER",
									Events: []Event{{Introduced: "0"}, {Fixed: "0.25.0"}},
								},
							},
						},
					},
				},
			},
		},
	}

	t.Run("finds exact match vulnerability", func(t *testing.T) {
		// Lookup with exact match returns both exact and subpackage vulns via prefix.
		dep := Dependency{Path: "golang.org/x/net", Version: "v0.20.0"}
		vulns := lookupCache(cache, dep)
		if len(vulns) != 2 {
			t.Fatalf("expected 2 vulns (exact + subpackage), got %d", len(vulns))
		}
		found := make(map[string]bool)
		for _, v := range vulns {
			found[v.ID] = true
		}
		if !found["GHSA-1234"] {
			t.Error("missing exact match vuln GHSA-1234")
		}
		if !found["GHSA-5678"] {
			t.Error("missing subpackage vuln GHSA-5678")
		}
	})

	t.Run("returns empty for unaffected version", func(t *testing.T) {
		// v0.25.0 is fixed for both exact (fixed at 0.23.0) and subpackage (fixed at 0.25.0).
		dep := Dependency{Path: "golang.org/x/net", Version: "v0.25.0"}
		vulns := lookupCache(cache, dep)
		if len(vulns) != 0 {
			t.Errorf("expected 0 vulns for fixed version, got %d", len(vulns))
		}
	})

	t.Run("returns empty for unknown package", func(t *testing.T) {
		dep := Dependency{Path: "github.com/unknown/pkg", Version: "v1.0.0"}
		vulns := lookupCache(cache, dep)
		if len(vulns) != 0 {
			t.Errorf("expected 0 vulns for unknown package, got %d", len(vulns))
		}
	})

	t.Run("finds subpackage vulnerabilities via prefix match", func(t *testing.T) {
		dep := Dependency{Path: "golang.org/x/net", Version: "v0.20.0"}
		vulns := lookupCache(cache, dep)
		// Should find both the exact match (GHSA-1234) and subpackage (GHSA-5678)
		// since golang.org/x/net is a prefix of golang.org/x/net/http2.
		found := make(map[string]bool)
		for _, v := range vulns {
			found[v.ID] = true
		}
		if !found["GHSA-1234"] {
			t.Error("missing exact match vuln GHSA-1234")
		}
		// Subpackage match: go.mod declares golang.org/x/net but vuln is in golang.org/x/net/http2.
		if !found["GHSA-5678"] {
			t.Error("missing subpackage vuln GHSA-5678")
		}
	})
}
