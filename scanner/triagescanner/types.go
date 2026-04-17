// Package triagescanner provides AI-assisted finding triage by collecting
// contextual evidence (source links, imports, middleware chains) for each
// scanner finding, enabling the user's AI to classify confirmed violations
// vs false positives.
package triagescanner

import "github.com/shyshlakov/pci-dss-mcp/scanner"

// TriageResult is the complete output of the triage tool.
type TriageResult struct {
	Findings   []EnrichedFinding `json:"findings"`
	Metadata   TriageMetadata    `json:"metadata"`
	NextCursor string            `json:"next_cursor,omitempty" jsonschema:"Opaque cursor token for resuming triage enrichment across pages. Empty when no more pages remain."`
}

// EnrichedFinding wraps a scanner.Finding with contextual evidence for AI triage.
type EnrichedFinding struct {
	Finding scanner.Finding `json:"finding"`
	Context FindingContext  `json:"context"`
	Hint    string          `json:"triage_hint"`
}

// FindingContext holds all contextual evidence collected for a finding.
//
// source bytes are no longer embedded in the response. Sources is a
// list of ResourceLink hints; the MCP client reads source on demand via
// its own Read tool per MCP spec 2025-06-18 resource_link content type.
// This caps triage_findings response size on large projects.
type FindingContext struct {
	Sources          []ResourceLink `json:"sources,omitempty"`
	Imports          []string       `json:"imports,omitempty"`
	PackageDecls     []string       `json:"package_decls,omitempty"`
	MiddlewareChain  []string       `json:"middleware_chain,omitempty"`
	RouterSetup      string         `json:"router_setup,omitempty"`
	ResponseType     string         `json:"response_type,omitempty"`
	DeclarationScope string         `json:"declaration_scope,omitempty"`
	EvidenceFiles    []string       `json:"evidence_files,omitempty"`
	FileLocation     string         `json:"file_location,omitempty"`
	TriageNotes      []string       `json:"triage_notes,omitempty"` // notes
}

// ResourceLink describes a source file reference per MCP spec 2025-06-18
// `resource_link` content type. The MCP client reads source via its own
// Read tool rather than the server embedding 20-30 lines per finding.
// replaces inline source embedding to cap triage response size.
type ResourceLink struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
	StartLine   int    `json:"start_line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
}

// TriageMetadata contains statistics about the triage operation.
type TriageMetadata struct {
	FindingsTotal   int   `json:"findings_total"`
	FindingsTriaged int   `json:"findings_triaged"`
	DurationMS      int64 `json:"duration_ms"`
	FilesAnalyzed   int   `json:"files_analyzed"`
}
