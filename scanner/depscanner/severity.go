package depscanner

import (
	"fmt"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// resolveSeverity implements a three-tier severity resolution chain per /:
//
// Tier 1: database_specific.severity (GHSA entries have this).
// Tier 2: Parse CVSS vector from severity[0].score if Tier 1 is empty.
// Tier 3: Default to HIGH if no severity data is available (conservative).
func resolveSeverity(vuln *Vulnerability) scanner.Severity {
	// Tier 1: database_specific.severity (direct mapping).
	if dbSev := vuln.DatabaseSpecific.Severity; dbSev != "" {
		switch strings.ToUpper(dbSev) {
		case "CRITICAL":
			return scanner.SeverityCritical
		case "HIGH":
			return scanner.SeverityHigh
		case "MODERATE":
			// OSV/GHSA uses "MODERATE" not "MEDIUM".
			return scanner.SeverityMedium
		case "MEDIUM":
			return scanner.SeverityMedium
		case "LOW":
			return scanner.SeverityLow
		}
	}

	// Tier 2: Parse CVSS vector.
	if len(vuln.SeverityData) > 0 {
		score, err := parseCVSSBaseScore(vuln.SeverityData[0].Score)
		if err == nil {
			switch {
			case score >= 9.0:
				return scanner.SeverityCritical
			case score >= 7.0:
				return scanner.SeverityHigh
			case score >= 4.0:
				return scanner.SeverityMedium
			case score >= 0.1:
				return scanner.SeverityLow
			}
		}
	}

	// Tier 3: Conservative default.
	return scanner.SeverityHigh
}

// parseCVSSBaseScore parses a CVSS vector string and returns the base score.
// Supports CVSS v2.0, v3.0, v3.1, and v4.0 vector formats.
func parseCVSSBaseScore(vectorString string) (float64, error) {
	switch {
	case strings.HasPrefix(vectorString, "CVSS:4.0/"):
		vec, err := gocvss40.ParseVector(vectorString)
		if err != nil {
			return 0, fmt.Errorf("parse CVSS 4.0: %w", err)
		}
		return vec.Score(), nil

	case strings.HasPrefix(vectorString, "CVSS:3.1/"):
		vec, err := gocvss31.ParseVector(vectorString)
		if err != nil {
			return 0, fmt.Errorf("parse CVSS 3.1: %w", err)
		}
		return vec.BaseScore(), nil

	case strings.HasPrefix(vectorString, "CVSS:3.0/"):
		vec, err := gocvss30.ParseVector(vectorString)
		if err != nil {
			return 0, fmt.Errorf("parse CVSS 3.0: %w", err)
		}
		return vec.BaseScore(), nil

	default:
		// Try CVSS v2.0 (format: "AV:N/AC:L/Au:N/C:C/I:C/A:C").
		vec, err := gocvss20.ParseVector(vectorString)
		if err != nil {
			return 0, fmt.Errorf("parse CVSS vector %q: %w", vectorString, err)
		}
		return vec.BaseScore(), nil
	}
}
