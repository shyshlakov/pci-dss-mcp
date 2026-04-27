package depscanner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultOSVGoZipURL = "https://storage.googleapis.com/osv-vulnerabilities/Go/all.zip"

func snapshotURL() string {
	if env := strings.TrimRight(os.Getenv("OSV_BASE_URL"), "/"); env != "" {
		return env + "/osv-vulnerabilities/Go/all.zip"
	}
	return defaultOSVGoZipURL
}

const (
	// maxDownloadSize caps the OSV ZIP download at 100 MB.
	maxDownloadSize = 100 * 1024 * 1024
)

// UpdateResult contains the result of a cache update operation.
type UpdateResult struct {
	CachePath         string     `json:"cache_path"`
	VulnCount         int        `json:"vuln_count"`
	DownloadSize      int64      `json:"download_size"`
	PreviousCacheDate *time.Time `json:"previous_cache_date,omitempty"`
}

func downloadAndBuildCache(ctx context.Context, outputPath string, zipURL string) (*UpdateResult, error) {
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, zipURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download vulnerability data: %w", err)
	}
	etag := resp.Header.Get("Etag")
	lastMod := resp.Header.Get("Last-Modified")
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close osv response body", "err", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	// Atomic write: temp file + os.Rename so a partial download never replaces
	// a good cache file.
	tmpFile, err := os.CreateTemp(outputDir, "osv-download-*.zip")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpZipPath := tmpFile.Name()
	defer func() {
		if rerr := os.Remove(tmpZipPath); rerr != nil && !os.IsNotExist(rerr) {
			slog.Warn("remove temp zip", "path", tmpZipPath, "err", rerr)
		}
	}()

	limitedReader := io.LimitReader(resp.Body, maxDownloadSize)
	downloadSize, err := io.Copy(tmpFile, limitedReader)
	if err != nil {
		if cerr := tmpFile.Close(); cerr != nil {
			slog.Warn("close temp file after copy error", "err", cerr)
		}
		return nil, fmt.Errorf("download to temp file: %w", err)
	}
	if cerr := tmpFile.Close(); cerr != nil {
		return nil, fmt.Errorf("close temp zip: %w", cerr)
	}

	zipReader, err := zip.OpenReader(tmpZipPath)
	if err != nil {
		return nil, fmt.Errorf("open ZIP: %w", err)
	}
	defer func() {
		if cerr := zipReader.Close(); cerr != nil {
			slog.Warn("close zip reader", "err", cerr)
		}
	}()

	cache := CacheFile{
		Generated: time.Now().UTC(),
		Source:    zipURL,
		Packages:  make(map[string][]Vulnerability),
	}

	for _, f := range zipReader.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		indexZipEntry(f, &cache)
	}

	data, err := json.Marshal(cache)
	if err != nil {
		return nil, fmt.Errorf("marshal cache: %w", err)
	}

	tmpOutput, err := os.CreateTemp(outputDir, "osv-cache-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp output: %w", err)
	}
	tmpOutputPath := tmpOutput.Name()

	if _, err := tmpOutput.Write(data); err != nil {
		if cerr := tmpOutput.Close(); cerr != nil {
			slog.Warn("close temp output after write error", "err", cerr)
		}
		if rerr := os.Remove(tmpOutputPath); rerr != nil && !os.IsNotExist(rerr) {
			slog.Warn("remove temp output after write error", "path", tmpOutputPath, "err", rerr)
		}
		return nil, fmt.Errorf("write temp cache: %w", err)
	}
	if cerr := tmpOutput.Close(); cerr != nil {
		return nil, fmt.Errorf("close temp cache: %w", cerr)
	}

	if err := os.Rename(tmpOutputPath, outputPath); err != nil {
		if rerr := os.Remove(tmpOutputPath); rerr != nil && !os.IsNotExist(rerr) {
			slog.Warn("remove temp output after rename error", "path", tmpOutputPath, "err", rerr)
		}
		return nil, fmt.Errorf("rename cache file: %w", err)
	}

	if merr := saveMeta(outputPath, cacheMeta{ETag: etag, LastModified: lastMod}); merr != nil {
		slog.Warn("save cache meta", "err", merr)
	}

	result := &UpdateResult{
		CachePath:    outputPath,
		VulnCount:    cache.VulnCount,
		DownloadSize: downloadSize,
	}

	return result, nil
}

// indexZipEntry opens one zip entry, decodes it as a Vulnerability, and
// indexes it into the cache. Non-JSON or malformed entries are logged and
// skipped; the scanner continues with the remaining entries.
func indexZipEntry(f *zip.File, cache *CacheFile) {
	rc, err := f.Open()
	if err != nil {
		return
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil {
			slog.Warn("close zip entry", "name", f.Name, "err", cerr)
		}
	}()

	var vuln Vulnerability
	if err := json.NewDecoder(rc).Decode(&vuln); err != nil {
		return
	}

	for _, aff := range vuln.Affected {
		if aff.Package.Ecosystem == "Go" {
			cache.Packages[aff.Package.Name] = append(cache.Packages[aff.Package.Name], vuln)
			cache.VulnCount++
		}
	}
}
