package depscanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// createTestZIP builds an in-memory ZIP file containing OSV vulnerability JSON entries.
func createTestZIP(vulns map[string]Vulnerability) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, vuln := range vulns {
		data, _ := json.Marshal(vuln)
		f, _ := w.Create(name)
		f.Write(data)
	}

	w.Close()
	return buf.Bytes()
}

func TestDownloadAndBuildCache(t *testing.T) {
	t.Parallel()
	goVuln := Vulnerability{
		ID:      "GHSA-go-1234",
		Summary: "Vulnerability in Go package",
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "0"}, {Fixed: "0.23.0"}}},
				},
			},
		},
	}

	goVuln2 := Vulnerability{
		ID:      "GHSA-go-5678",
		Summary: "Another Go vulnerability",
		Affected: []Affected{
			{
				Package: AffectedPackage{Name: "github.com/gin-gonic/gin", Ecosystem: "Go"},
				Ranges: []Range{
					{Type: "SEMVER", Events: []Event{{Introduced: "1.0.0"}, {Fixed: "1.10.0"}}},
				},
			},
		},
	}

	zipData := createTestZIP(map[string]Vulnerability{
		"GHSA-go-1234.json": goVuln,
		"GHSA-go-5678.json": goVuln2,
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	defer server.Close()

	t.Run("creates cache file with correct structure", func(t *testing.T) {
		dir := t.TempDir()
		outputPath := filepath.Join(dir, "go-osv-test.json")

		result, err := downloadAndBuildCache(context.Background(), outputPath, server.URL)
		if err != nil {
			t.Fatalf("downloadAndBuildCache() error: %v", err)
		}

		if result.CachePath != outputPath {
			t.Errorf("CachePath = %q, want %q", result.CachePath, outputPath)
		}
		if result.VulnCount != 2 {
			t.Errorf("VulnCount = %d, want 2", result.VulnCount)
		}

		// Verify the cache file is valid JSON.
		data, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatalf("ReadFile error: %v", err)
		}

		var cache CacheFile
		if err := json.Unmarshal(data, &cache); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if cache.VulnCount != 2 {
			t.Errorf("cache.VulnCount = %d, want 2", cache.VulnCount)
		}
		if cache.Generated.IsZero() {
			t.Error("cache.Generated should not be zero")
		}
		if len(cache.Packages) != 2 {
			t.Errorf("cache.Packages length = %d, want 2", len(cache.Packages))
		}
		if _, ok := cache.Packages["golang.org/x/net"]; !ok {
			t.Error("cache.Packages missing golang.org/x/net")
		}
		if _, ok := cache.Packages["github.com/gin-gonic/gin"]; !ok {
			t.Error("cache.Packages missing github.com/gin-gonic/gin")
		}
	})

	t.Run("creates cache directory if it does not exist", func(t *testing.T) {
		dir := t.TempDir()
		nestedDir := filepath.Join(dir, "a", "b", "c")
		outputPath := filepath.Join(nestedDir, "go-osv-test.json")

		_, err := downloadAndBuildCache(context.Background(), outputPath, server.URL)
		if err != nil {
			t.Fatalf("downloadAndBuildCache() error: %v", err)
		}

		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			t.Error("output file should exist after download")
		}
	})

	t.Run("atomic write - output file exists", func(t *testing.T) {
		dir := t.TempDir()
		outputPath := filepath.Join(dir, "go-osv-test.json")

		_, err := downloadAndBuildCache(context.Background(), outputPath, server.URL)
		if err != nil {
			t.Fatalf("downloadAndBuildCache() error: %v", err)
		}

		// Verify no temp files left behind.
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() != "go-osv-test.json" {
				t.Errorf("unexpected file in output dir: %s (temp file not cleaned up?)", e.Name())
			}
		}
	})

	t.Run("only indexes Go ecosystem entries", func(t *testing.T) {
		// Create a ZIP with a non-Go vulnerability.
		nonGoVuln := Vulnerability{
			ID:      "GHSA-py-9999",
			Summary: "Python vulnerability",
			Affected: []Affected{
				{
					Package: AffectedPackage{Name: "flask", Ecosystem: "PyPI"},
					Ranges: []Range{
						{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}}},
					},
				},
			},
		}

		mixedZip := createTestZIP(map[string]Vulnerability{
			"GHSA-go-1234.json": goVuln,
			"GHSA-py-9999.json": nonGoVuln,
		})

		mixedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(mixedZip)
		}))
		defer mixedServer.Close()

		dir := t.TempDir()
		outputPath := filepath.Join(dir, "go-osv-test.json")

		result, err := downloadAndBuildCache(context.Background(), outputPath, mixedServer.URL)
		if err != nil {
			t.Fatalf("downloadAndBuildCache() error: %v", err)
		}

		// Only Go vuln should be counted.
		if result.VulnCount != 1 {
			t.Errorf("VulnCount = %d, want 1 (only Go vulns)", result.VulnCount)
		}

		data, _ := os.ReadFile(outputPath)
		var cache CacheFile
		json.Unmarshal(data, &cache)

		if _, ok := cache.Packages["flask"]; ok {
			t.Error("cache should not contain non-Go packages")
		}
	})

	t.Run("skips non-JSON files in ZIP", func(t *testing.T) {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)

		// Add a JSON vulnerability.
		data, _ := json.Marshal(goVuln)
		f, _ := w.Create("GHSA-go-1234.json")
		f.Write(data)

		// Add a non-JSON file.
		f2, _ := w.Create("README.md")
		f2.Write([]byte("# Readme"))

		w.Close()

		nonJsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(buf.Bytes())
		}))
		defer nonJsonServer.Close()

		dir := t.TempDir()
		outputPath := filepath.Join(dir, "go-osv-test.json")

		result, err := downloadAndBuildCache(context.Background(), outputPath, nonJsonServer.URL)
		if err != nil {
			t.Fatalf("downloadAndBuildCache() error: %v", err)
		}

		if result.VulnCount != 1 {
			t.Errorf("VulnCount = %d, want 1 (only .json files processed)", result.VulnCount)
		}
	})
}
