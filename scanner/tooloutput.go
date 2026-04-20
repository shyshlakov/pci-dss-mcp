package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ScannerToolOutput is the typed MCP output struct returned by every
// single-scanner tool.go handler. The MCP SDK auto-infers OutputSchema
// from the jsonschema struct tags here. Each scanner-specific
// tool.go returns *ScannerToolOutput directly so clients can parse the
// structured response without text-blob JSON extraction.
//
// Keep this struct in the scanner package (not per-scanner) so every
// tool gets an identical output shape, making it trivial for MCP
// clients to generalize over "any scanner tool result".
type ScannerToolOutput struct {
	ResponseShape string          `json:"response_shape" jsonschema:"Response-shape discriminator (flat for ScannerToolOutput)"`
	Scanner       string          `json:"scanner" jsonschema:"Scanner identifier (e.g. pan_data, encryption)"`
	Findings      []Finding       `json:"findings" jsonschema:"Findings detected by this scanner. May be empty."`
	SeverityStats SeverityStats   `json:"severity_stats" jsonschema:"Count of findings by severity tier"`
	Summary       *ScannerSummary `json:"summary,omitempty" jsonschema:"Full-scan summary (by_severity and top-10 by_rule histogram) computed over the unfiltered finding set. Present on Layer A flat responses emitted by hybrid-migrated tools; lets a filtered call answer both 'how many HIGH+ findings' and 'how many of each rule/severity in total' in one shot."`
	Metadata      ScanMetadata    `json:"metadata" jsonschema:"Scan execution metadata (files scanned, duration)"`
	TotalFindings int             `json:"total_findings,omitempty" jsonschema:"Total findings for this scan (includes results beyond this page). Present when the scanner tool paginates."`
	NextCursor    string          `json:"next_cursor,omitempty" jsonschema:"Opaque cursor token for resuming this scanner's pagination (10-minute TTL). Empty when no more pages remain or pagination is not active."`
}

// SeverityStats holds per-severity finding counts for an MCP tool output.
type SeverityStats struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// RuleCount pairs a rule_id with its occurrence count. Used as an entry in
// the top-N by_rule histogram emitted by ScannerSummary.
type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

// ScannerSummary is the canonical full-scan summary block carried on hybrid
// tools' Layer A flat responses. by_severity reflects the FULL unfiltered
// scan (not the filtered finding page); by_rule is the top-10 histogram
// sorted count-desc / rule_id-asc with more_rules recording the overflow.
type ScannerSummary struct {
	BySeverity SeverityStats `json:"by_severity"`
	ByRule     []RuleCount   `json:"by_rule"`
	MoreRules  int           `json:"more_rules,omitempty"`
}

// Returns non-nil even for zero findings so the OutputSchema is stable.
func BuildScannerToolOutput(scannerName string, result *ScanResult) *ScannerToolOutput {
	if result == nil {
		return &ScannerToolOutput{
			ResponseShape: "flat",
			Scanner:       scannerName,
			Findings:      []Finding{},
		}
	}
	findings := result.Findings
	if findings == nil {
		findings = []Finding{}
	}
	counts := CountBySeverity(findings)
	return &ScannerToolOutput{
		ResponseShape: "flat",
		Scanner:       scannerName,
		Findings:      findings,
		SeverityStats: SeverityStats{
			Critical: counts[SeverityCritical],
			High:     counts[SeverityHigh],
			Medium:   counts[SeverityMedium],
			Low:      counts[SeverityLow],
			Info:     counts[SeverityInfo],
		},
		Metadata: result.Metadata,
	}
}

func ParseScannerToolOutput(result *mcp.CallToolResult) (*ScannerToolOutput, error) {
	if result == nil {
		return nil, fmt.Errorf("nil CallToolResult")
	}
	if result.StructuredContent == nil {
		return nil, fmt.Errorf("CallToolResult.StructuredContent is nil")
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil, fmt.Errorf("marshal StructuredContent: %w", err)
	}
	var out ScannerToolOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("unmarshal StructuredContent: %w", err)
	}
	return &out, nil
}

// HasRuleID reports whether any finding in the output has the given rule ID.
// Intended as a convenience for integration tests.
func (o *ScannerToolOutput) HasRuleID(ruleID string) bool {
	if o == nil {
		return false
	}
	for _, f := range o.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// HasSeverity reports whether any finding has the given severity.
func (o *ScannerToolOutput) HasSeverity(sev Severity) bool {
	if o == nil {
		return false
	}
	for _, f := range o.Findings {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

// HasFilePathContains reports whether any finding's FilePath contains the
// given substring (filename or path fragment).
func (o *ScannerToolOutput) HasFilePathContains(substr string) bool {
	if o == nil {
		return false
	}
	for _, f := range o.Findings {
		if strings.Contains(f.FilePath, substr) {
			return true
		}
	}
	return false
}

// HasRequirementID reports whether any finding is mapped to requirementID
// via either its primary RequirementID or RelatedRequirements slice.
func (o *ScannerToolOutput) HasRequirementID(requirementID string) bool {
	if o == nil {
		return false
	}
	for _, f := range o.Findings {
		if f.RequirementID == requirementID {
			return true
		}
		for _, r := range f.RelatedRequirements {
			if r == requirementID {
				return true
			}
		}
	}
	return false
}

// HasDescriptionContains reports whether any finding's Description contains
// the given substring.
func (o *ScannerToolOutput) HasDescriptionContains(substr string) bool {
	if o == nil {
		return false
	}
	for _, f := range o.Findings {
		if strings.Contains(f.Description, substr) {
			return true
		}
	}
	return false
}
