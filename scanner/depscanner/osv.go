// Package depscanner implements PCI DSS 6.3.3 dependency vulnerability scanning.
//
// It parses go.mod for direct dependencies and checks them against the OSV.dev
// vulnerability database (online or offline). This package contains OSV data types,
// severity resolution, version range matching, and deduplication logic.
package depscanner

import (
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Vulnerability represents a single OSV vulnerability entry.
type Vulnerability struct {
	ID               string           `json:"id"`
	Summary          string           `json:"summary"`
	Aliases          []string         `json:"aliases"`
	SeverityData     []SeverityEntry  `json:"severity"`
	DatabaseSpecific DatabaseSpecific `json:"database_specific"`
	Affected         []Affected       `json:"affected"`
	Modified         string           `json:"modified"`
}

// SeverityEntry holds a CVSS vector string and its type.
type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// DatabaseSpecific holds the database_specific.severity field from GHSA entries.
type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

// Affected describes an affected package and its version ranges.
type Affected struct {
	Package  AffectedPackage `json:"package"`
	Ranges   []Range         `json:"ranges"`
	Versions []string        `json:"versions"`
}

// AffectedPackage identifies a package by name and ecosystem.
type AffectedPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Range describes a version range with events (introduced, fixed, last_affected).
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event marks a version boundary (introduced, fixed, or last_affected).
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

// CacheFile is the local cache format for offline vulnerability scanning.
type CacheFile struct {
	Generated time.Time                  `json:"generated"`
	Source    string                     `json:"source"`
	VulnCount int                        `json:"vuln_count"`
	Packages  map[string][]Vulnerability `json:"packages"`
}

// Dependency represents a single dependency parsed from go.mod.
type Dependency struct {
	Path    string
	Version string
	Line    int
}

// isAffected checks if a module version falls within any of the given affected ranges.
// It normalizes OSV versions (no "v" prefix) to go.mod format ("v" prefix) before comparison.
func isAffected(moduleVersion string, ranges []Range) bool {
	for _, r := range ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		affected := false
		for _, event := range r.Events {
			if event.Introduced != "" {
				if event.Introduced == "0" {
					// "0" means all versions from the beginning.
					affected = true
				} else {
					osvVer := normalizeVersion(event.Introduced)
					if semver.Compare(moduleVersion, osvVer) >= 0 {
						affected = true
					}
				}
			}
			if event.Fixed != "" {
				osvVer := normalizeVersion(event.Fixed)
				if semver.Compare(moduleVersion, osvVer) >= 0 {
					affected = false
				}
			}
		}
		if affected {
			return true
		}
	}
	return false
}

// normalizeVersion adds a "v" prefix if not present (OSV versions lack it).
func normalizeVersion(version string) string {
	if !strings.HasPrefix(version, "v") {
		return "v" + version
	}
	return version
}

// deduplicateVulns groups vulnerabilities that share CVE/GHSA/GO aliases and returns
// one representative per unique vulnerability. Prefers entries with severity data (GHSA).
func deduplicateVulns(vulns []*Vulnerability) []*Vulnerability {
	// Build a union-find based on shared aliases.
	// aliasToGroup maps each ID/alias to a group key.
	aliasToGroup := make(map[string]string)
	groups := make(map[string][]*Vulnerability)

	for _, v := range vulns {
		allIDs := collectAllIDs(v)

		// Find existing group for any of this vuln's IDs.
		var groupKey string
		for _, id := range allIDs {
			if gk, ok := aliasToGroup[id]; ok {
				groupKey = gk
				break
			}
		}

		if groupKey == "" {
			// New group: use the vuln's primary ID as key.
			groupKey = v.ID
		}

		// Assign all IDs to this group.
		for _, id := range allIDs {
			aliasToGroup[id] = groupKey
		}

		groups[groupKey] = append(groups[groupKey], v)
	}

	// For each group, pick the best representative.
	result := make([]*Vulnerability, 0, len(groups))
	for _, group := range groups {
		best := pickBest(group)
		// Merge all IDs from the group into the best entry's aliases.
		mergedIDs := make(map[string]bool)
		for _, v := range group {
			mergedIDs[v.ID] = true
			for _, alias := range v.Aliases {
				mergedIDs[alias] = true
			}
		}
		// Remove the best's own ID from aliases.
		delete(mergedIDs, best.ID)
		best.Aliases = make([]string, 0, len(mergedIDs))
		for id := range mergedIDs {
			best.Aliases = append(best.Aliases, id)
		}
		result = append(result, best)
	}

	return result
}

// collectAllIDs returns the vuln ID plus all aliases.
func collectAllIDs(v *Vulnerability) []string {
	ids := make([]string, 0, 1+len(v.Aliases))
	ids = append(ids, v.ID)
	ids = append(ids, v.Aliases...)
	return ids
}

// pickBest selects the vulnerability entry with the best severity data.
// Prefers GHSA entries (have database_specific.severity) over GO entries.
func pickBest(group []*Vulnerability) *Vulnerability {
	var best *Vulnerability
	for _, v := range group {
		if best == nil {
			best = v
			continue
		}
		// Prefer entry with database_specific severity.
		if v.DatabaseSpecific.Severity != "" && best.DatabaseSpecific.Severity == "" {
			best = v
		}
		// Among entries with severity, prefer GHSA over GO.
		if strings.HasPrefix(v.ID, "GHSA-") && !strings.HasPrefix(best.ID, "GHSA-") {
			best = v
		}
	}
	return best
}
