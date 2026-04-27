package depscanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CacheStaleness represents the staleness tier of a vulnerability cache.
type CacheStaleness int

const (
	// CacheFresh indicates cache is less than 7 days old.
	CacheFresh CacheStaleness = iota
	// CacheStale indicates cache is 7-14 days old (MEDIUM warning).
	CacheStale
	// CacheCritical indicates cache is more than 14 days old (HIGH warning).
	CacheCritical
)

const (
	cacheEnvVar           = "PCI_MCP_CACHE_DIR"
	defaultCacheDir       = ".pci-dss-mcp/vuln-cache"
	cacheFilePrefix       = "go-osv-"
	cacheFileSuffix       = ".json"
	cacheDateFormat       = "2006-01-02"
	staleDaysThreshold    = 7
	criticalDaysThreshold = 14
)

const (
	ruleDepCacheCold  = "DEP-CACHE-COLD"
	ruleDepCacheStale = "DEP-CACHE-STALE"
	ruleDepCacheNoDir = "DEP-CACHE-NO-DIR"
)

func resolveCachePath() (string, error) {
	if envDir := os.Getenv(cacheEnvVar); envDir != "" {
		return envDir, nil
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "pci-dss-mcp", "vuln-cache"), nil
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, defaultCacheDir), nil
	}
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		return filepath.Join(base, "pci-dss-mcp", "vuln-cache"), nil
	}
	return "", errors.New("cache directory cannot be determined: set PCI_MCP_CACHE_DIR")
}

// latestCacheFile finds the most recent go-osv-YYYY-MM-DD.json file in the given directory.
// Returns the full path, parsed date, and any error. Returns error if no matching files found.
func latestCacheFile(cacheDir string) (string, time.Time, error) {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read cache directory %s: %w", cacheDir, err)
	}

	var latestPath string
	var latestDate time.Time

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, cacheFilePrefix) || !strings.HasSuffix(name, cacheFileSuffix) {
			continue
		}

		// Extract date from filename: go-osv-YYYY-MM-DD.json.
		dateStr := strings.TrimPrefix(name, cacheFilePrefix)
		dateStr = strings.TrimSuffix(dateStr, cacheFileSuffix)

		date, err := time.Parse(cacheDateFormat, dateStr)
		if err != nil {
			// Skip files with unparseable dates.
			continue
		}

		if latestPath == "" || date.After(latestDate) {
			latestPath = filepath.Join(cacheDir, name)
			latestDate = date
		}
	}

	if latestPath == "" {
		return "", time.Time{}, fmt.Errorf("no cache files found in %s", cacheDir)
	}

	return latestPath, latestDate, nil
}

// loadCache reads a cache file and unmarshals it into a CacheFile struct.
func loadCache(path string) (*CacheFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cache file: %w", err)
	}

	var cache CacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("parse cache file: %w", err)
	}

	return &cache, nil
}

// checkStaleness determines the staleness tier of a cache based on its date.
func checkStaleness(cacheDate time.Time) CacheStaleness {
	age := time.Since(cacheDate)
	days := int(age.Hours() / 24)

	switch {
	case days >= criticalDaysThreshold+1:
		return CacheCritical
	case days >= staleDaysThreshold:
		return CacheStale
	default:
		return CacheFresh
	}
}

// stalenessWarning returns a warning message based on cache staleness.
// Returns empty string for Fresh caches.
func stalenessWarning(staleness CacheStaleness, cacheDate time.Time) string {
	days := int(math.Round(time.Since(cacheDate).Hours() / 24))

	switch staleness {
	case CacheStale:
		return fmt.Sprintf(
			"Vulnerability cache is %d days old. Run update_vulnerability_db to ensure latest CVEs are detected. New vulnerabilities are published continuously.",
			days,
		)
	case CacheCritical:
		return fmt.Sprintf(
			"Vulnerability cache is %d+ days old. Critical CVEs published since last update may be missed. PCI DSS 6.3.3 requires timely detection. Update immediately.",
			days,
		)
	default:
		return ""
	}
}

// cacheAgeMessage returns a human-readable cache age string.
// Format: "Offline scan using cache from YYYY-MM-DD (N days ago)".
func cacheAgeMessage(cacheDate time.Time) string {
	days := int(math.Round(time.Since(cacheDate).Hours() / 24))
	return fmt.Sprintf("Offline scan using cache from %s (%d days ago)",
		cacheDate.Format(cacheDateFormat), days)
}

func durationHuman(d time.Duration) string {
	hours := int(d.Hours())
	if hours < 48 {
		return fmt.Sprintf("%dh", hours)
	}
	days := hours / 24
	rem := hours % 24
	return fmt.Sprintf("%dd %dh", days, rem)
}

// lookupCache finds vulnerabilities for a dependency in the cache.
// Checks both exact match on dep.Path and prefix match (OSV package may be
// subpackage like golang.org/x/net/http2 while go.mod has golang.org/x/net).
// For each matched vuln, checks isAffected with the dependency version.
func lookupCache(cache *CacheFile, dep Dependency) []*Vulnerability {
	var result []*Vulnerability

	for pkgName, vulns := range cache.Packages {
		// Match if exact package or if the cached package is a subpackage of dep.Path.
		if pkgName != dep.Path && !strings.HasPrefix(pkgName, dep.Path+"/") {
			continue
		}

		for i := range vulns {
			vuln := &vulns[i]
			for _, aff := range vuln.Affected {
				if aff.Package.Name != pkgName {
					continue
				}
				if isAffected(dep.Version, aff.Ranges) {
					result = append(result, vuln)
					break
				}
			}
		}
	}

	return result
}
