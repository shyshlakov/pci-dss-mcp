// Package scanner defines shared types for all PCI DSS compliance scanners.
//
// This package has NO dependency on the MCP SDK. It contains pure domain types
// used by every scanner implementation.
package scanner

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
)

// Severity represents the severity level of a compliance finding.
type Severity string

const (
	// SeverityCritical indicates a direct PCI DSS violation.
	SeverityCritical Severity = "CRITICAL"
	// SeverityHigh indicates a potential PCI DSS violation.
	SeverityHigh Severity = "HIGH"
	// SeverityMedium indicates a best practice violation.
	SeverityMedium Severity = "MEDIUM"
	// SeverityLow indicates a low-severity finding requiring tracking per PCI DSS.
	SeverityLow Severity = "LOW"
	// SeverityInfo indicates an informational finding (e.g., test variable auto-suppression).
	SeverityInfo Severity = "INFO"
)

// Finding represents a single compliance violation or warning detected by a scanner.
type Finding struct {
	RuleID              string   `json:"rule_id"`
	Severity            Severity `json:"severity"`
	RequirementID       string   `json:"requirement_id"`
	FilePath            string   `json:"file_path"`
	Line                int      `json:"line"`
	Column              int      `json:"column,omitempty"`
	Description         string   `json:"description"`
	Suggestion          string   `json:"suggestion"`
	RelatedRequirements []string `json:"related_requirements,omitempty"`

	// metadata enrichment.
	Confidence         string       `json:"confidence,omitempty"`          // "high", "medium", "low"
	DevContext         bool         `json:"dev_context,omitempty"`         // true if dev/local path or placeholder value
	CodeSnippet        *CodeSnippet `json:"code_snippet,omitempty"`        // +-2 lines around finding
	TriageHint         string       `json:"triage_hint,omitempty"`         // why scanner flagged this
	FixHint            string       `json:"fix_hint,omitempty"`            // actionable fix suggestion
	MiddlewareDetected bool         `json:"middleware_detected,omitempty"` // for AUDIT/AUTH rules
	SQLPatternMatched  bool         `json:"sql_pattern_matched,omitempty"` // for CRYPTO Tier 2/3
}

// CodeSnippet captures source context around a finding for AI-assisted triage.
type CodeSnippet struct {
	Before string `json:"before"` // up to 2 lines before the finding
	Line   string `json:"line"`   // the flagged line
	After  string `json:"after"`  // up to 2 lines after the finding
}

// ScanMetadata contains metadata about a scan execution.
type ScanMetadata struct {
	ScannedFiles int   `json:"scanned_files"`
	ScannedLines int   `json:"scanned_lines"`
	DurationMS   int64 `json:"duration_ms"`
}

// ScanResult contains the findings and metadata from a scan execution.
type ScanResult struct {
	Findings []Finding    `json:"findings"`
	Metadata ScanMetadata `json:"metadata"`
}

// Scanner is the interface all PCI DSS compliance scanners implement.
type Scanner interface {
	// Name returns the scanner identifier (e.g., "pan_data", "encryption").
	Name() string
	// Description returns a human-readable description of what this scanner checks.
	Description() string
	// Scan analyzes the target path and returns findings.
	Scan(ctx context.Context, targetPath string) (*ScanResult, error)
	// Requirements returns PCI DSS requirement IDs this scanner covers.
	Requirements() []string
}

// PackageContextAwareScanner is implemented by scanners that consume
// pre-built keywords.PackageInfo via the multi-signal payment-context
// scorer. Scanners that do NOT implement this interface
// continue to work via Scan / ScanFull and may build PackageInfo lazily
// via keywords.PackageInfoFromFile. The pkgCtx map is keyed by package
// directory relative to targetPath; absent keys mean "no pre-built
// package context" and implementers MUST fall back without panicking.
type PackageContextAwareScanner interface {
	ScanWithPackageContext(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool, pkgCtx map[string]*keywords.PackageInfo) (*ScanResult, error)
}
