package depscanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const canonicalCacheFile = "go-osv.json"

const (
	cacheFreshTTL  = 24 * time.Hour
	cacheStaleTTL  = 7 * 24 * time.Hour
)

type cacheState struct {
	coldCache     bool
	staleFallback bool
	noWritableDir bool
	cacheAge      time.Duration
}

var (
	coldWarnOnce  sync.Once
	staleWarnOnce sync.Once
)

func canonicalCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, canonicalCacheFile)
}

func ensureCacheFresh(ctx context.Context, cacheDir string) cacheState {
	if cacheDir == "" {
		return cacheState{noWritableDir: true}
	}

	cachePath := canonicalCachePath(cacheDir)

	info, statErr := os.Stat(cachePath)
	if statErr != nil {
		if legacyPath, _, lerr := latestCacheFile(cacheDir); lerr == nil {
			info2, sErr := os.Stat(legacyPath)
			if sErr == nil {
				legacyAge := time.Since(info2.ModTime())
				if legacyAge < cacheFreshTTL {
					return cacheState{cacheAge: legacyAge}
				}
				if legacyAge > cacheStaleTTL {
					if dlErr := refreshCache(ctx, cachePath); dlErr != nil {
						staleWarnOnce.Do(func() {
							slog.Warn("OSV legacy cache force-refresh failed, using stale cache", "err", dlErr)
						})
						return cacheState{staleFallback: true, cacheAge: legacyAge}
					}
					return cacheState{cacheAge: legacyAge}
				}
				meta, _ := loadMeta(legacyPath)
				resp, ok200, cgErr := conditionalGet(ctx, snapshotURL(), meta)
				if cgErr != nil {
					staleWarnOnce.Do(func() {
						slog.Warn("OSV legacy revalidation failed, using stale cache", "err", cgErr)
					})
					return cacheState{staleFallback: true, cacheAge: legacyAge}
				}
				if ok200 {
					if cerr := resp.Body.Close(); cerr != nil {
						slog.Warn("close 200 body before re-download", "err", cerr)
					}
					if dlErr := refreshCache(ctx, cachePath); dlErr != nil {
						staleWarnOnce.Do(func() {
							slog.Warn("OSV legacy refresh failed after 200 signal, using stale cache", "err", dlErr)
						})
						return cacheState{staleFallback: true, cacheAge: legacyAge}
					}
					return cacheState{cacheAge: legacyAge}
				}
				now := time.Now()
				if cerr := os.Chtimes(legacyPath, now, now); cerr != nil {
					slog.Warn("chtimes after 304 (legacy)", "err", cerr)
				}
				return cacheState{cacheAge: legacyAge}
			}
		}
		if dlErr := refreshCacheIfMissing(ctx, cachePath); dlErr != nil {
			if errors.Is(dlErr, errLockBusy) {
				if _, recheck := os.Stat(cachePath); recheck == nil {
					return cacheState{}
				}
			}
			if !cacheDirWritable(cacheDir) {
				return cacheState{noWritableDir: true}
			}
			coldWarnOnce.Do(func() {
				slog.Warn("OSV cache cold, network refresh failed", "err", dlErr)
			})
			return cacheState{coldCache: true}
		}
		return cacheState{}
	}

	age := time.Since(info.ModTime())

	if age < cacheFreshTTL {
		return cacheState{cacheAge: age}
	}

	if age > cacheStaleTTL {
		if dlErr := refreshCache(ctx, cachePath); dlErr != nil {
			staleWarnOnce.Do(func() {
				slog.Warn("OSV cache force-refresh failed, using stale cache", "err", dlErr)
			})
			return cacheState{staleFallback: true, cacheAge: age}
		}
		return cacheState{cacheAge: age}
	}

	meta, _ := loadMeta(cachePath)
	resp, ok200, cgErr := conditionalGet(ctx, snapshotURL(), meta)
	if cgErr != nil {
		staleWarnOnce.Do(func() {
			slog.Warn("OSV revalidation failed, using stale cache", "err", cgErr)
		})
		return cacheState{staleFallback: true, cacheAge: age}
	}
	if ok200 {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close 200 body before re-download", "err", cerr)
		}
		if dlErr := refreshCache(ctx, cachePath); dlErr != nil {
			staleWarnOnce.Do(func() {
				slog.Warn("OSV refresh failed after 200 signal, using stale cache", "err", dlErr)
			})
			return cacheState{staleFallback: true, cacheAge: age}
		}
		return cacheState{cacheAge: age}
	}
	now := time.Now()
	if cerr := os.Chtimes(cachePath, now, now); cerr != nil {
		slog.Warn("chtimes after 304", "err", cerr)
	}
	return cacheState{cacheAge: age}
}

func refreshCache(ctx context.Context, cachePath string) error {
	return refreshCacheLocked(ctx, cachePath, false)
}

func refreshCacheIfMissing(ctx context.Context, cachePath string) error {
	return refreshCacheLocked(ctx, cachePath, true)
}

func refreshCacheLocked(ctx context.Context, cachePath string, skipIfPresent bool) error {
	return withCacheLock(ctx, cachePath, func() error {
		if skipIfPresent {
			if info, statErr := os.Stat(cachePath); statErr == nil {
				age := time.Since(info.ModTime())
				if age < cacheFreshTTL {
					return nil
				}
			}
		}
		_, err := downloadAndBuildCache(ctx, cachePath, snapshotURL())
		return err
	})
}

func cacheDirWritable(cacheDir string) bool {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return false
	}
	probe := filepath.Join(cacheDir, ".pci-mcp-write-probe")
	f, err := os.Create(probe)
	if err != nil {
		return false
	}
	if cerr := f.Close(); cerr != nil {
		slog.Warn("close write probe", "err", cerr)
	}
	if rerr := os.Remove(probe); rerr != nil {
		slog.Warn("remove write probe", "err", rerr)
	}
	return true
}

type cacheMeta struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
}

func loadMeta(path string) (cacheMeta, error) {
	data, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return cacheMeta{}, err
	}
	var m cacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return cacheMeta{}, fmt.Errorf("parse cache meta: %w", err)
	}
	return m, nil
}

func saveMeta(path string, m cacheMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal cache meta: %w", err)
	}
	return os.WriteFile(path+".meta.json", data, 0o644)
}

func conditionalGet(ctx context.Context, url string, m cacheMeta) (*http.Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("conditional GET: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusNotModified:
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close 304 body", "err", cerr)
		}
		return nil, false, nil
	case http.StatusOK:
		return resp, true, nil
	default:
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close non-200 body", "err", cerr)
		}
		return nil, false, fmt.Errorf("conditional GET: unexpected status %d", resp.StatusCode)
	}
}
