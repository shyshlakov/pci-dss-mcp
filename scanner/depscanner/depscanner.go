package depscanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// DependencyScanner scans go.mod dependencies for known vulnerabilities.
// Implements scanner.Scanner interface.
type DependencyScanner struct {
	osvClient *OSVClient
}

// New creates a new DependencyScanner instance with an OSV client.
func New() *DependencyScanner {
	return &DependencyScanner{
		osvClient: NewOSVClient(),
	}
}

// Name returns the scanner identifier.
func (s *DependencyScanner) Name() string {
	return "dependency_vulnerability"
}

// Description returns a human-readable description of this scanner.
func (s *DependencyScanner) Description() string {
	return "Scan go.mod dependencies for known vulnerabilities via OSV.dev (PCI DSS 6.3.3)"
}

// Requirements returns PCI DSS requirement IDs this scanner covers.
func (s *DependencyScanner) Requirements() []string {
	return []string{"6.3.3"}
}

// Scan analyzes the target path for dependency vulnerabilities using "auto" mode.
// Implements the scanner.Scanner interface.
func (s *DependencyScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithMode(ctx, targetPath, "auto")
}

func (s *DependencyScanner) ScanWithMode(ctx context.Context, targetPath string, mode string) (*scanner.ScanResult, error) {
	if mode == "" {
		mode = "auto"
	}

	start := time.Now()

	deps, err := parseGoMod(targetPath)
	if err != nil {
		return nil, fmt.Errorf("parse dependencies: %w", err)
	}

	if mode != "auto" {
		return nil, fmt.Errorf("unknown scan mode: %q (supported: auto)", mode)
	}

	result, err := s.scanFromCache(deps)
	if err != nil {
		return nil, err
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	result.Metadata.ScannedFiles = 1

	return result, nil
}

func (s *DependencyScanner) scanFromCache(deps []Dependency) (*scanner.ScanResult, error) {
	cacheDir := resolveCachePath()

	cachePath, cacheDate, err := latestCacheFile(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("no vulnerability cache available: %w. Run update_vulnerability_db to download OSV cache", err)
	}

	cache, err := loadCache(cachePath)
	if err != nil {
		return nil, fmt.Errorf("load cache: %w", err)
	}

	staleness := checkStaleness(cacheDate)

	// Build findings from cache.
	var allVulns []*Vulnerability
	depVulnMap := make(map[string][]*Vulnerability)
	for _, dep := range deps {
		vulns := lookupCache(cache, dep)
		if len(vulns) > 0 {
			depVulnMap[dep.Path] = vulns
			allVulns = append(allVulns, vulns...)
		}
	}

	// Deduplicate all found vulns.
	deduped := deduplicateVulns(allVulns)

	// Build findings from deduplicated vulns.
	dedupedSet := make(map[string]bool)
	for _, v := range deduped {
		dedupedSet[v.ID] = true
	}

	var findings []scanner.Finding
	for _, dep := range deps {
		vulns := depVulnMap[dep.Path]
		for _, vuln := range vulns {
			if !dedupedSet[vuln.ID] {
				continue
			}
			fixVersion := extractFixVersion(vuln, dep.Path)
			findings = append(findings, buildFinding(dep, vuln, fixVersion))
			// Remove from deduped set so we don't produce duplicate findings.
			delete(dedupedSet, vuln.ID)
		}
	}

	// Add staleness warning as a finding.
	if staleness != CacheFresh {
		warningText := stalenessWarning(staleness, cacheDate)
		var severity scanner.Severity
		if staleness == CacheStale {
			severity = scanner.SeverityMedium
		} else {
			severity = scanner.SeverityHigh
		}
		findings = append(findings, scanner.Finding{
			RuleID:        "DEP-CACHE-STALE",
			Severity:      severity,
			RequirementID: "6.3.3",
			FilePath:      "go.mod",
			Description:   warningText,
			Suggestion:    "Run update_vulnerability_db to refresh OSV cache",
		})
	}

	// Always include cache age info.
	ageMsg := cacheAgeMessage(cacheDate)
	slog.Info(ageMsg)

	return &scanner.ScanResult{
		Findings: findings,
		Metadata: scanner.ScanMetadata{},
	}, nil
}

// parseGoMod reads and parses go.mod from the given directory, returning
// only direct dependencies with their paths, versions, and line numbers.
// Resolves targetPath to absolute path per T-08-01.
func parseGoMod(targetPath string) ([]Dependency, error) {
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	goModPath := filepath.Join(absPath, "go.mod")

	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}

	f, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}

	var deps []Dependency
	for _, req := range f.Require {
		// Skip indirect dependencies per plan requirement.
		if req.Indirect {
			continue
		}

		line := 0
		if req.Syntax != nil {
			line = req.Syntax.Start.Line
		}

		deps = append(deps, Dependency{
			Path:    req.Mod.Path,
			Version: req.Mod.Version,
			Line:    line,
		})
	}

	return deps, nil
}

// buildFinding constructs a scanner.Finding from a dependency and its vulnerability.
// Follows (FilePath=go.mod), (description format), (suggestion format)
// (RequirementID=6.3.3), (PCI context notes).
func buildFinding(dep Dependency, vuln *Vulnerability, fixVersion string) scanner.Finding {
	severity := resolveSeverity(vuln)

	desc := fmt.Sprintf("%s in %s@%s: %s",
		formatVulnIDs(vuln),
		dep.Path,
		dep.Version,
		vuln.Summary,
	)

	affectedRange := extractAffectedRange(vuln, dep.Path)
	if affectedRange != "" {
		desc += fmt.Sprintf(" Affected: %s.", affectedRange)
	}

	if fixVersion != "" {
		desc += fmt.Sprintf(" Fix: %s.", fixVersion)
	} else {
		desc += " Fix: no fix available."
	}

	// Add CVSS score if available.
	if len(vuln.SeverityData) > 0 {
		score, err := parseCVSSBaseScore(vuln.SeverityData[0].Score)
		if err == nil {
			desc += fmt.Sprintf(" CVSS: %.1f.", score)
		}
	}

	// Add PCI context note.
	desc += " " + pciContextNote(severity)

	var suggestion string
	if fixVersion != "" {
		suggestion = fmt.Sprintf("Run 'go get %s@%s'", dep.Path, fixVersion)
	} else {
		suggestion = "No fix available -- consider replacing dependency or pinning to unaffected version"
	}

	return scanner.Finding{
		RuleID:        "DEP-VULN",
		Severity:      severity,
		RequirementID: "6.3.3",
		FilePath:      "go.mod",
		Line:          dep.Line,
		Description:   desc,
		Suggestion:    suggestion,
	}
}

// extractFixVersion finds the fixed version from affected ranges matching the module path.
// Returns empty string if no fix is available.
func extractFixVersion(vuln *Vulnerability, modulePath string) string {
	for _, aff := range vuln.Affected {
		if aff.Package.Name != modulePath {
			continue
		}
		for _, r := range aff.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return normalizeVersion(event.Fixed)
				}
			}
		}
	}
	return ""
}

// extractAffectedRange returns a human-readable affected version range string.
func extractAffectedRange(vuln *Vulnerability, modulePath string) string {
	for _, aff := range vuln.Affected {
		if aff.Package.Name != modulePath {
			continue
		}
		for _, r := range aff.Ranges {
			var introduced, fixed string
			for _, event := range r.Events {
				if event.Introduced != "" {
					if event.Introduced == "0" {
						introduced = "v0.0.0"
					} else {
						introduced = normalizeVersion(event.Introduced)
					}
				}
				if event.Fixed != "" {
					fixed = normalizeVersion(event.Fixed)
				}
			}
			if introduced != "" && fixed != "" {
				return fmt.Sprintf(">=%s, <%s", introduced, fixed)
			}
			if introduced != "" {
				return fmt.Sprintf(">=%s", introduced)
			}
		}
	}
	return ""
}

// formatVulnIDs joins the vulnerability ID and aliases with " / ".
func formatVulnIDs(vuln *Vulnerability) string {
	ids := []string{vuln.ID}
	ids = append(ids, vuln.Aliases...)
	return strings.Join(ids, " / ")
}

// pciContextNote returns a PCI DSS context note based on severity.
func pciContextNote(sev scanner.Severity) string {
	switch sev {
	case scanner.SeverityCritical, scanner.SeverityHigh, scanner.SeverityMedium:
		return "PCI DSS 6.3.3 requires remediation within 30 days."
	case scanner.SeverityLow:
		return "CVSS < 4.0: below ASV scan failure threshold, but PCI DSS requires tracking and remediation plan."
	default:
		return ""
	}
}
