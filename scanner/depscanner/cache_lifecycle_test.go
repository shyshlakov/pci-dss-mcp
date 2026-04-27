package depscanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func writeFreshCacheFile(t *testing.T, cacheDir string) string {
	t.Helper()
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	cachePath := filepath.Join(cacheDir, "go-osv.json")
	body := `{"generated":"2026-04-26T00:00:00Z","source":"test","vuln_count":1,"packages":{"github.com/go-jose/go-jose/v4":[{"id":"GHSA-test-go-jose","summary":"test advisory","aliases":[],"affected":[{"package":{"name":"github.com/go-jose/go-jose/v4","ecosystem":"Go"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"v4.1.4"}]}]}]}]}}`
	if err := os.WriteFile(cachePath, []byte(body), 0o644); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	return cachePath
}

func writeSidecarMeta(t *testing.T, cachePath, etag, lastModified string) {
	t.Helper()
	meta := `{"etag":"` + etag + `","last_modified":"` + lastModified + `"}`
	if err := os.WriteFile(cachePath+".meta.json", []byte(meta), 0o644); err != nil {
		t.Fatalf("write sidecar meta: %v", err)
	}
}

func setFileMtime(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func findInfoFinding(findings []scanner.Finding, ruleID string) (scanner.Finding, bool) {
	for _, f := range findings {
		if f.RuleID == ruleID && f.Severity == scanner.SeverityInfo {
			return f, true
		}
	}
	return scanner.Finding{}, false
}

func countFindingsByRule(findings []scanner.Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

func TestCacheLifecycle(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "cache_hit_fresh",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				setFileMtime(t, cachePath, time.Now().Add(-2*time.Hour))

				var requestCount int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					atomic.AddInt32(&requestCount, 1)
					w.WriteHeader(http.StatusInternalServerError)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected at least one DEP-VULN finding from fresh cache")
				}
				if got := atomic.LoadInt32(&requestCount); got != 0 {
					t.Errorf("fresh cache scan made %d outbound requests; want 0", got)
				}
			},
		},
		{
			name: "cache_miss_cold",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()

				var getCount int32
				srv, _, _ := newRecordingOSVServer(t)
				defer srv.Close()
				_ = atomic.LoadInt32(&getCount)

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan cold cache: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding from cold cache + snapshot download")
				}
				cachePath := filepath.Join(cacheDir, "go-osv.json")
				if _, statErr := os.Stat(cachePath); statErr != nil {
					t.Errorf("expected cache file at %s after cold-cache scan: %v", cachePath, statErr)
				}
				metaPath := cachePath + ".meta.json"
				if _, statErr := os.Stat(metaPath); statErr != nil {
					t.Errorf("expected sidecar meta at %s after cold-cache scan: %v", metaPath, statErr)
				}
			},
		},
		{
			name: "cache_miss_cold_uncreated_dir",
			run: func(t *testing.T) {
				parent := t.TempDir()
				cacheDir := filepath.Join(parent, "pci-dss-mcp", "vuln-cache")

				if _, statErr := os.Stat(cacheDir); statErr == nil {
					t.Fatalf("test precondition: cacheDir must not exist before scan, got existing %s", cacheDir)
				}

				srv, _, _ := newRecordingOSVServer(t)
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after fresh dir + refresh; got 0")
				}
				if _, present := findInfoFinding(result.Findings, "DEP-CACHE-COLD"); present {
					t.Errorf("DEP-CACHE-COLD INFO must not emit when refresh succeeds")
				}
				if _, present := findInfoFinding(result.Findings, "DEP-CACHE-NO-DIR"); present {
					t.Errorf("DEP-CACHE-NO-DIR INFO must not emit when dir is creatable")
				}
				cachePath := filepath.Join(cacheDir, "go-osv.json")
				if _, statErr := os.Stat(cachePath); statErr != nil {
					t.Errorf("expected cache file at %s after refresh: %v", cachePath, statErr)
				}
				metaPath := cachePath + ".meta.json"
				if _, statErr := os.Stat(metaPath); statErr != nil {
					t.Errorf("expected sidecar meta at %s after refresh: %v", metaPath, statErr)
				}
			},
		},
		{
			name: "revalidate_304",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				past := time.Now().Add(-25 * time.Hour)
				setFileMtime(t, cachePath, past)
				writeSidecarMeta(t, cachePath, `"test-etag-1234"`, past.UTC().Format(http.TimeFormat))

				var getCount int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
						atomic.AddInt32(&getCount, 1)
						w.WriteHeader(http.StatusNotModified)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				bodyBefore, err := os.ReadFile(cachePath)
				if err != nil {
					t.Fatalf("read cache: %v", err)
				}

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after 304 revalidate")
				}
				if got := atomic.LoadInt32(&getCount); got != 1 {
					t.Errorf("revalidate_304: GET count = %d; want 1", got)
				}
				bodyAfter, err := os.ReadFile(cachePath)
				if err != nil {
					t.Fatalf("read cache after: %v", err)
				}
				if string(bodyBefore) != string(bodyAfter) {
					t.Errorf("304 revalidate must not rewrite cache body")
				}
				info, statErr := os.Stat(cachePath)
				if statErr != nil {
					t.Fatalf("stat cache: %v", statErr)
				}
				if info.ModTime().Before(time.Now().Add(-1 * time.Hour)) {
					t.Errorf("304 revalidate must bump cache mtime; got %v", info.ModTime())
				}
			},
		},
		{
			name: "revalidate_200",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				past := time.Now().Add(-25 * time.Hour)
				setFileMtime(t, cachePath, past)
				writeSidecarMeta(t, cachePath, `"old-etag"`, past.UTC().Format(http.TimeFormat))

				srv, _, _ := newRecordingOSVServer(t)
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after 200 refresh")
				}
				if _, statErr := os.Stat(cachePath); statErr != nil {
					t.Errorf("cache file missing after 200 refresh: %v", statErr)
				}
			},
		},
		{
			name: "force_refresh_gt7d",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				past := time.Now().Add(-8 * 24 * time.Hour)
				setFileMtime(t, cachePath, past)
				writeSidecarMeta(t, cachePath, `"old-etag"`, past.UTC().Format(http.TimeFormat))

				var sawConditionalHeader int32
				zipBody := buildMinimalGoOSVZip(t)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
						if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
							atomic.StoreInt32(&sawConditionalHeader, 1)
						}
						w.Header().Set("ETag", `"new-etag"`)
						w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
						w.Header().Set("Content-Type", "application/zip")
						if _, werr := w.Write(zipBody); werr != nil {
							t.Logf("server write zip: %v", werr)
						}
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after force-refresh")
				}
				if atomic.LoadInt32(&sawConditionalHeader) != 0 {
					t.Errorf("force_refresh_gt7d must not send If-None-Match or If-Modified-Since")
				}
			},
		},
		{
			name: "corrupted_cache",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := filepath.Join(cacheDir, "go-osv.json")
				if err := os.WriteFile(cachePath, []byte(`{"generated":"2026-04`), 0o644); err != nil {
					t.Fatalf("write corrupt cache: %v", err)
				}

				srv, _, _ := newRecordingOSVServer(t)
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan with corrupt cache must recover, got: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after corrupt-cache recovery")
				}
			},
		},
		{
			name: "parallel_cold_cache",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()

				var getCount int32
				zipBody := buildMinimalGoOSVZip(t)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
						atomic.AddInt32(&getCount, 1)
						time.Sleep(50 * time.Millisecond)
						w.Header().Set("ETag", `"parallel-etag"`)
						w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
						w.Header().Set("Content-Type", "application/zip")
						if _, werr := w.Write(zipBody); werr != nil {
							t.Logf("server write zip: %v", werr)
						}
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				var wg sync.WaitGroup
				results := make([]int, 2)
				wg.Add(2)
				for i := 0; i < 2; i++ {
					i := i
					go func() {
						defer wg.Done()
						res, err := New().Scan(context.Background(), fixturePath(t))
						if err != nil {
							t.Errorf("parallel scan %d: %v", i, err)
							return
						}
						results[i] = countFindingsByRule(res.Findings, "DEP-VULN")
					}()
				}
				wg.Wait()

				if results[0] != results[1] {
					t.Errorf("parallel scans returned different DEP-VULN counts: %d vs %d", results[0], results[1])
				}
				if got := atomic.LoadInt32(&getCount); got != 1 {
					t.Errorf("parallel cold cache: file-lock must serialize refresh; GET count = %d, want 1", got)
				}
			},
		},
		{
			name: "stale_fallback_network_failed",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				past := time.Now().Add(-8 * 24 * time.Hour)
				setFileMtime(t, cachePath, past)

				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					hj, ok := w.(http.Hijacker)
					if !ok {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					conn, _, hjerr := hj.Hijack()
					if hjerr != nil {
						return
					}
					if cerr := conn.Close(); cerr != nil {
						t.Logf("hijack close: %v", cerr)
					}
				}))
				srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan with stale cache + network failure must succeed: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding from stale cache fallback")
				}
				stale, found := findInfoFinding(result.Findings, "DEP-CACHE-STALE")
				if !found {
					t.Errorf("expected DEP-CACHE-STALE INFO finding on actual stale fallback")
				} else {
					if stale.RequirementID != "6.3.3" {
						t.Errorf("DEP-CACHE-STALE requirement_id = %q; want 6.3.3", stale.RequirementID)
					}
					if stale.FilePath != "go.mod" {
						t.Errorf("DEP-CACHE-STALE file_path = %q; want go.mod", stale.FilePath)
					}
					if strings.Contains(stale.Description, cachePath) {
						t.Errorf("DEP-CACHE-STALE description must not contain cache file path; got: %s", stale.Description)
					}
				}
				if n := countFindingsByRule(result.Findings, "DEP-CACHE-STALE"); n != 1 {
					t.Errorf("expected exactly one DEP-CACHE-STALE finding, got %d", n)
				}
			},
		},
		{
			name: "corrupted_meta_json",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				cachePath := writeFreshCacheFile(t, cacheDir)
				past := time.Now().Add(-25 * time.Hour)
				setFileMtime(t, cachePath, past)
				if err := os.WriteFile(cachePath+".meta.json", []byte("{not valid json"), 0o644); err != nil {
					t.Fatalf("write corrupt meta: %v", err)
				}

				var sawConditionalHeader int32
				zipBody := buildMinimalGoOSVZip(t)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
						if r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "" {
							atomic.StoreInt32(&sawConditionalHeader, 1)
						}
						w.Header().Set("ETag", `"refreshed-etag"`)
						w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
						w.Header().Set("Content-Type", "application/zip")
						if _, werr := w.Write(zipBody); werr != nil {
							t.Logf("server write zip: %v", werr)
						}
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan with corrupt sidecar must recover: %v", err)
				}
				if countFindingsByRule(result.Findings, "DEP-VULN") == 0 {
					t.Errorf("expected DEP-VULN finding after corrupt-sidecar recovery")
				}
				if atomic.LoadInt32(&sawConditionalHeader) != 0 {
					t.Errorf("corrupt sidecar must yield unconditional GET (no If-None-Match / If-Modified-Since)")
				}
				meta, mErr := loadMeta(filepath.Join(cacheDir, "go-osv.json"))
				if mErr != nil {
					t.Errorf("expected sidecar meta refreshed to valid JSON, got: %v", mErr)
				}
				if meta.ETag != `"refreshed-etag"` {
					t.Errorf("expected refreshed sidecar ETag = \"refreshed-etag\"; got %q", meta.ETag)
				}
			},
		},
		{
			name: "subpackage_match_preserved",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()

				zipBody := buildOSVZip(t,
					osvEntry{
						id:         "GHSA-test-go-jose-jwt-subpath",
						pkg:        "github.com/go-jose/go-jose/v4/jwt",
						fixedAtVer: "v999.0.0",
					},
				)
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
						w.Header().Set("ETag", `"subpkg-etag"`)
						w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
						w.Header().Set("Content-Type", "application/zip")
						if _, werr := w.Write(zipBody); werr != nil {
							t.Logf("server write zip: %v", werr)
						}
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				defer srv.Close()

				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", srv.URL)

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan: %v", err)
				}
				matched := false
				for _, f := range result.Findings {
					if f.RuleID != "DEP-VULN" {
						continue
					}
					if strings.Contains(f.Description, "github.com/go-jose/go-jose/v4") || strings.Contains(f.Suggestion, "github.com/go-jose/go-jose/v4") {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("expected DEP-VULN finding for go-jose/v4 (sub-path match preserved on go-jose/v4/jwt OSV entry); got %d findings, none mentioning go-jose/v4", len(result.Findings))
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}

func TestAirGappedScan(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "cold_cache_no_network",
			run: func(t *testing.T) {
				cacheDir := t.TempDir()
				t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)
				t.Setenv("OSV_BASE_URL", "http://127.0.0.1:1")

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan air-gapped cold-cache must succeed gracefully: %v", err)
				}
				if n := countFindingsByRule(result.Findings, "DEP-VULN"); n != 0 {
					t.Errorf("expected 0 DEP-VULN findings on air-gapped cold cache, got %d", n)
				}
				cold, found := findInfoFinding(result.Findings, "DEP-CACHE-COLD")
				if !found {
					t.Fatalf("expected DEP-CACHE-COLD INFO finding")
				}
				if cold.RequirementID != "6.3.3" {
					t.Errorf("DEP-CACHE-COLD requirement_id = %q; want 6.3.3", cold.RequirementID)
				}
				if cold.FilePath != "go.mod" {
					t.Errorf("DEP-CACHE-COLD file_path = %q; want go.mod", cold.FilePath)
				}
				if !strings.Contains(cold.Description, "cache") {
					t.Errorf("DEP-CACHE-COLD description must mention 'cache'; got: %s", cold.Description)
				}
				if !strings.Contains(cold.Description, "network") && !strings.Contains(cold.Description, "bind-mount") {
					t.Errorf("DEP-CACHE-COLD description must mention 'network' or 'bind-mount'; got: %s", cold.Description)
				}
			},
		},
		{
			name: "no_writable_dir",
			run: func(t *testing.T) {
				baseDir := t.TempDir()
				notADir := filepath.Join(baseDir, "notdir")
				if err := os.WriteFile(notADir, []byte("not a dir"), 0o644); err != nil {
					t.Fatalf("write blocker file: %v", err)
				}

				t.Setenv("PCI_MCP_CACHE_DIR", notADir)
				t.Setenv("HOME", "")
				t.Setenv("XDG_CACHE_HOME", "")
				t.Setenv("OSV_BASE_URL", "http://127.0.0.1:1")

				result, err := New().Scan(context.Background(), fixturePath(t))
				if err != nil {
					t.Fatalf("scan with no writable cache dir must succeed gracefully: %v", err)
				}
				if n := countFindingsByRule(result.Findings, "DEP-VULN"); n != 0 {
					t.Errorf("expected 0 DEP-VULN findings when no writable cache dir, got %d", n)
				}
				noDir, found := findInfoFinding(result.Findings, "DEP-CACHE-NO-DIR")
				if !found {
					t.Fatalf("expected DEP-CACHE-NO-DIR INFO finding")
				}
				if noDir.RequirementID != "6.3.3" {
					t.Errorf("DEP-CACHE-NO-DIR requirement_id = %q; want 6.3.3", noDir.RequirementID)
				}
				if noDir.FilePath != "go.mod" {
					t.Errorf("DEP-CACHE-NO-DIR file_path = %q; want go.mod", noDir.FilePath)
				}
				if !strings.Contains(noDir.Description, "PCI_MCP_CACHE_DIR") {
					t.Errorf("DEP-CACHE-NO-DIR description must mention 'PCI_MCP_CACHE_DIR'; got: %s", noDir.Description)
				}
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}
