package scanner

import (
	"path/filepath"
	"strings"
)

// DevContext holds the result of dev-context classification for a finding.
// Used by scanners to adjust severity for dev/local/test files (to).
type DevContext struct {
	IsDevPath     bool // file is in a dev/local/test directory
	IsProdPath    bool // file is in a prod/k8s directory ( override)
	IsPlaceholder bool // value matches a placeholder pattern
	// true when path is inside a dedicated-dev directory
	// (dev/, local/, development/, sandbox/, dev/local/). Distinct from
	// IsDevPath which also fires for testdata/, test/, fixtures/, e2e/, docker/.
	// Callers downgrade findings FURTHER to INFO when this is set.
	DedicatedDev bool
	ExamplesPath bool
	OriginalSev  Severity // severity before adjustment
	AdjustedSev  Severity // severity after dev-context adjustment
	Label        string   // "dev-context" or "" for report annotation
}

// prodPathSegments are directory segments that indicate production config.
// If ANY segment matches, prod override is applied.
var prodPathSegments = []string{
	"prod", "production", "k8s", "kubernetes",
}

// prodFilePatterns are filename patterns that indicate production config.
var prodFilePatterns = []string{
	".env.prod", ".env.production",
}

// prodPathPrefixes are path prefixes for config directories.
var prodPathPrefixes = []string{
	"config/prod.", "config/prod/", "config/production.", "config/production/",
}

// devPathSegments are directory segments that indicate dev/test environment.
// "testdata" is intentionally excluded: it is a Go language convention for
// static fixtures with no dev-environment semantics. Including it caused
// silent downgrades of every finding inside testdata/ trees, including the
// golden fixture itself.
var devPathSegments = []string{
	"dev", "local", "docker", "fixtures", "test", "testseed", "e2e",
	"example", "examples", "sample", "samples",
}

var examplesSegments = map[string]bool{
	"example":  true,
	"examples": true,
	"sample":   true,
	"samples":  true,
}

// dedicatedDevSegments are directory segments that indicate a dedicated dev
// environment. A path inside any of these triggers the DedicatedDev
// flag, prompting callers to downgrade credential findings to INFO.
// NOTE: these are a STRICT SUBSET of devPathSegments -- "fixtures", "e2e",
// "docker" are intentionally NOT dedicated-dev because they mix source code
// and configs. "test" is safe because _test.go files are already excluded
// from scanning entirely; only helper/fixture files in test/
// directories are scanned.
var dedicatedDevSegments = []string{
	"dev", "local", "development", "sandbox", "test", "testseed",
	"example", "examples", "sample", "samples",
}

// devFilePatterns are filename patterns that indicate dev environment.
// NOTE: docker-compose.yml (no suffix) is NOT a dev pattern.
// Only docker-compose.{dev,local,override}.* match.
var devFilePatterns = []string{
	"docker-compose.dev.", "docker-compose.local.", "docker-compose.override.",
	".env.local", ".env.dev", ".env.development",
	".env.example", ".env.sample", ".env.template",
	"config.example.", "config.sample.",
}

// placeholderValues are case-insensitive exact values that indicate placeholders.
var placeholderValues = []string{
	"password", "changeme", "secret", "example",
	"localhost", "127.0.0.1", "test123", "dummy", "placeholder",
}

// ClassifyDevContext classifies a file path + value pair for dev-context
// severity adjustment. Prod path override is checked FIRST and is
// non-negotiable -- even placeholder values in prod configs stay CRITICAL.
//
// Delegates to ClassifyDevContextInRoot with an empty projectRoot, which
// preserves legacy full-path segment matching. Prefer the InRoot variant in
// scanners so ancestor-directory segments (e.g. testdata/, fixtures/) are
// stripped before matching.
func ClassifyDevContext(filePath string, value string, originalSev Severity) DevContext {
	return ClassifyDevContextInRoot(filePath, value, originalSev, "")
}

// ClassifyDevContextInRoot is ClassifyDevContext with the scan root plumbed
// through so isDevPath can strip ancestor segments before checking for dev
// markers. An empty projectRoot preserves the legacy full-path behavior.
func ClassifyDevContextInRoot(filePath string, value string, originalSev Severity, projectRoot string) DevContext {
	dc := DevContext{OriginalSev: originalSev, AdjustedSev: originalSev}

	// Prod path override -- always CRITICAL, check FIRST.
	if isProdPath(filePath) {
		dc.IsProdPath = true
		dc.AdjustedSev = SeverityCritical
		return dc
	}

	dc.IsDevPath = isDevPath(filePath, projectRoot)
	dc.IsPlaceholder = isPlaceholderValue(value)
	// set DedicatedDev flag for paths in dedicated dev
	// directories. The classifier does NOT apply an extra downgrade here --
	// callers consult dc.DedicatedDev and downgrade to Info themselves
	//. This keeps the classifier pure and pushes policy to callers.
	dc.DedicatedDev = isDedicatedDevPath(filePath)
	dc.ExamplesPath = isExamplesPath(filePath, projectRoot)

	var candidate Severity
	switch {
	case dc.IsDevPath && dc.IsPlaceholder:
		candidate = SeverityInfo
		dc.Label = "dev-context"
	case dc.IsDevPath:
		candidate = SeverityMedium
		dc.Label = "dev-context"
	case dc.IsPlaceholder:
		candidate = SeverityMedium
		dc.Label = "dev-context"
	default:
		return dc
	}

	// Dev-context only downgrades severity, never upgrades it. If the scanner
	// already assigned a lower severity (e.g., authscanner INFO for placeholders),
	// keep the original.
	if severityRank(candidate) < severityRank(originalSev) {
		dc.AdjustedSev = candidate
	}

	return dc
}

// severityRank returns a numeric rank for severity ordering.
// Higher rank = more severe.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// isProdPath returns true if the file path matches production path patterns.
func isProdPath(filePath string) bool {
	normalized := filepath.ToSlash(filePath)
	lower := strings.ToLower(normalized)

	// Check directory segments.
	segments := strings.Split(lower, "/")
	for _, seg := range segments {
		for _, prod := range prodPathSegments {
			if seg == prod {
				return true
			}
		}
	}

	// Check filename patterns.
	base := filepath.Base(lower)
	for _, pat := range prodFilePatterns {
		if base == pat {
			return true
		}
	}

	// Check path prefixes (config/prod.*, config/production.*).
	for _, prefix := range prodPathPrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}

	return false
}

// isDevPath returns true if the file path matches dev/local/test patterns.
// docker-compose.yml (no suffix) does NOT match.
//
// When projectRoot is non-empty, the function strips the projectRoot prefix
// before splitting into segments — so ancestor directories like /tmp/testdata
// or $HOME/dev do not incorrectly flag every file inside a scanned tree.
// An empty projectRoot preserves the legacy full-path behavior for callers
// that do not have a scan root available.
func isDevPath(filePath string, projectRoot string) bool {
	normalized := filepath.ToSlash(filePath)
	lower := strings.ToLower(normalized)

	// D-path-dep: match only on segments INSIDE the scanned tree. Falls
	// through to the full-path form on Rel errors or empty projectRoot.
	pathForSegments := lower
	if projectRoot != "" {
		rel, err := filepath.Rel(projectRoot, filePath)
		if err == nil {
			pathForSegments = strings.ToLower(filepath.ToSlash(rel))
		}
	}

	// Check directory segments.
	segments := strings.Split(pathForSegments, "/")
	for _, seg := range segments {
		for _, dev := range devPathSegments {
			if seg == dev {
				return true
			}
		}
	}

	// Check filename patterns (base name only — unaffected by projectRoot).
	base := filepath.Base(lower)
	for _, pat := range devFilePatterns {
		if strings.HasPrefix(base, pat) || base == pat {
			return true
		}
	}

	return false
}

// isPlaceholderValue returns true if the value exactly matches (case-insensitive)
// a known placeholder pattern.
func isPlaceholderValue(value string) bool {
	lower := strings.ToLower(value)
	for _, p := range placeholderValues {
		if lower == p {
			return true
		}
	}
	return false
}

// isDedicatedDevPath returns true if ANY directory segment in filePath matches
// dedicatedDevSegments. Uses forward-slash normalization + exact segment
// equality so path-traversal tokens like "." never match.
func isDedicatedDevPath(filePath string) bool {
	normalized := filepath.ToSlash(filePath)
	lower := strings.ToLower(normalized)
	segments := strings.Split(lower, "/")
	for _, seg := range segments {
		for _, dd := range dedicatedDevSegments {
			if seg == dd {
				return true
			}
		}
	}
	return false
}

func isExamplesPath(filePath string, projectRoot string) bool {
	normalized := filepath.ToSlash(filePath)
	lower := strings.ToLower(normalized)

	pathForSegments := lower
	if projectRoot != "" {
		rel, err := filepath.Rel(projectRoot, filePath)
		if err == nil {
			pathForSegments = strings.ToLower(filepath.ToSlash(rel))
		}
	}

	for _, seg := range strings.Split(pathForSegments, "/") {
		if examplesSegments[seg] {
			return true
		}
	}
	return false
}
