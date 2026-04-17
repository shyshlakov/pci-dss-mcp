package reportscanner

import (
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// ComplianceReport is the full JSON compliance report.
type ComplianceReport struct {
	Metadata          ReportMetadata               `json:"metadata"`
	Summary           ReportSummary                `json:"summary"`
	ScanSummary       *ScanSummary                 `json:"scan_summary,omitempty"`
	RequirementStatus map[string]RequirementStatus `json:"requirement_status"`
	Findings          []ReportFinding              `json:"findings"` // kept for backward compat
	FindingsByRule    []FindingsByRule             `json:"findings_by_rule,omitempty"`
	Suppressions      []SuppressionEntry           `json:"suppressions"`
	NotChecked        []NotCheckedEntry            `json:"not_checked"`
}

// FindingsByRule groups findings by rule_id for AI pattern recognition.
// Groups are sorted by severity (CRITICAL first), then by count (highest first).
type FindingsByRule struct {
	RuleID      string          `json:"rule_id"`
	Severity    string          `json:"severity"`
	Requirement string          `json:"requirement"`
	Count       int             `json:"count"`
	Instances   []ReportFinding `json:"instances"`
}

// ScanSummary provides AI-consumable scan metadata at the top level.
type ScanSummary struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"` // scanner name grouping
	ScannedFiles  int            `json:"scanned_files"`
	DurationMS    int64          `json:"duration_ms"`
	AITriageHint  string         `json:"ai_triage_hint,omitempty"`
}

// RequirementStatus tracks the compliance status for one PCI DSS requirement.
type RequirementStatus struct {
	RequirementID string `json:"requirement_id"`
	Title         string `json:"title"`
	Status        string `json:"status"` // PASS, FAIL, WARNING, SUPPRESSED, NOT_CHECKED
	FindingCount  int    `json:"finding_count,omitempty"`
	// Accuracy annotations for detectable requirements.
	CoverageScope string   `json:"coverage_scope,omitempty"`
	Limitations   []string `json:"limitations,omitempty"`
	NotCovered    string   `json:"not_covered,omitempty"`
	// Cross-reference for related requirements.
	CrossReference string `json:"cross_reference,omitempty"`
}

// ReportFinding wraps a scanner.Finding with report-level fields.
type ReportFinding struct {
	scanner.Finding
	RequirementTitle string `json:"requirement_title"`
	ScannerName      string `json:"scanner_name"`
}

// SuppressionEntry records a suppressed finding with audit trail.
type SuppressionEntry struct {
	ReportFinding
	Reason string `json:"reason"`
	Source string `json:"source"` // "inline comment" or ".pci-dss-mcp-ignore:N"
}

// NotCheckedEntry documents why a requirement cannot be verified by static analysis.
type NotCheckedEntry struct {
	RequirementID string `json:"requirement_id"`
	Title         string `json:"title"`
	Explanation   string `json:"explanation"`
	// Parent coverage note.
	CoveredBy        string `json:"covered_by,omitempty"`
	TestingProcedure string `json:"testing_procedure,omitempty"`
}

// ReportMetadata contains scan execution metadata.
type ReportMetadata struct {
	GeneratedAt  string `json:"generated_at"`
	TargetPath   string `json:"target_path"`
	TotalFiles   int    `json:"total_files"`
	TotalLines   int    `json:"total_lines"`
	DurationMS   int64  `json:"duration_ms"`
	ScannerCount int    `json:"scanner_count"`
}

// ReportSummary contains aggregate counts.
type ReportSummary struct {
	TotalRequirements int `json:"total_requirements"`
	Checked           int `json:"checked"`
	NotCheckedCount   int `json:"not_checked"`
	Pass              int `json:"pass"`
	Fail              int `json:"fail"`
	Warning           int `json:"warning"`
	Suppressed        int `json:"suppressed"`
	Critical          int `json:"critical_findings"`
	High              int `json:"high_findings"`
	Medium            int `json:"medium_findings"`
	Low               int `json:"low_findings"`
	Info              int `json:"info_findings"`
}

type SummaryResponse struct {
	ResponseShape       string                       `json:"response_shape"`
	Metadata            ReportMetadata               `json:"metadata"`
	Summary             ReportSummary                `json:"summary"`
	RequirementStatuses map[string]RequirementStatus `json:"requirement_statuses"`
	TopFindings         map[string][]ReportFinding   `json:"top_findings"`
	Pagination          PaginationInfo               `json:"pagination"`
}

type FlatResponse struct {
	ResponseShape string          `json:"response_shape"`
	Metadata      ReportMetadata  `json:"metadata"`
	Summary       ReportSummary   `json:"summary"`
	Findings      []ReportFinding `json:"findings"`
	Pagination    PaginationInfo  `json:"pagination"`
}

type PaginationInfo struct {
	TotalFindings        int            `json:"total_findings"`
	Returned             int            `json:"returned"`
	RemainingPerSeverity map[string]int `json:"remaining_per_severity,omitempty"`
	NextCursor           string         `json:"next_cursor,omitempty"`
	Hint                 string         `json:"hint"`
	AutoCapped           bool           `json:"auto_capped"`
	TotalBeforeCap       int            `json:"total_before_cap,omitempty"`
	Kept                 int            `json:"kept,omitempty"`
}

type CursorExpiredError struct {
	ResponseShape string `json:"response_shape"`
	Error         string `json:"error"`
	Code          string `json:"code"`
	Hint          string `json:"hint"`
}

type cacheEntry struct {
	findings   []ReportFinding
	scanMeta   ReportMetadata
	summary    ReportSummary
	reqStatus  map[string]RequirementStatus
	filterHash string
	createdAt  time.Time
	expiresAt  time.Time
}
