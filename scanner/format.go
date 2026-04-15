package scanner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// FormatResult converts a ScanResult into an MCP CallToolResult with text/plain content.
//
// Output format:
// - Zero findings: "No violations found." followed by scan metadata.
// - Non-zero findings: Three-part format:
// Part 1: Summary line "N CRITICAL, N HIGH, N MEDIUM findings"
// Part 2: Per-finding blocks separated by "---"
// Part 3: "JSON:" followed by JSON array of findings
//
// All output is text/plain via mcp.TextContent. No emojis.
func FormatResult(result *ScanResult, scannerName string) *mcp.CallToolResult {
	if len(result.Findings) == 0 {
		return formatZeroFindings(result.Metadata)
	}
	return formatFindings(result)
}

// formatZeroFindings returns a clean scan result with metadata.
func formatZeroFindings(meta ScanMetadata) *mcp.CallToolResult {
	text := fmt.Sprintf("No violations found.\nScanned %d files, %d lines in %dms.",
		meta.ScannedFiles, meta.ScannedLines, meta.DurationMS)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: text},
		},
	}
}

// formatFindings returns the three-part output for non-zero findings.
func formatFindings(result *ScanResult) *mcp.CallToolResult {
	var sb strings.Builder

	// Part 1: Summary line
	counts := CountBySeverity(result.Findings)
	fmt.Fprintf(&sb, "%d CRITICAL, %d HIGH, %d MEDIUM, %d LOW, %d INFO findings\n",
		counts[SeverityCritical], counts[SeverityHigh], counts[SeverityMedium], counts[SeverityLow], counts[SeverityInfo])

	// Part 2: Per-finding blocks
	for i, f := range result.Findings {
		if i > 0 {
			sb.WriteString("---\n")
		}
		fmt.Fprintf(&sb, "[%s] %s (Requirement %s)\n", f.Severity, f.Description, f.RequirementID)
		fmt.Fprintf(&sb, "  %s:%d\n", f.FilePath, f.Line)
		fmt.Fprintf(&sb, "  Suggestion: %s\n", f.Suggestion)
		fmt.Fprintf(&sb, "  Suppress: // pci-ignore: <reason>\n")
		if len(f.RelatedRequirements) > 0 {
			fmt.Fprintf(&sb, "  Also satisfies: %s\n", strings.Join(f.RelatedRequirements, ", "))
		}
	}

	// Part 3: JSON array
	sb.WriteString("---\nJSON:\n")
	jsonBytes, err := json.Marshal(result.Findings)
	if err != nil {
		// Should not happen with well-formed findings, but handle gracefully.
		fmt.Fprintf(&sb, "[]\n")
	} else {
		sb.Write(jsonBytes)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: sb.String()},
		},
	}
}

// CountBySeverity returns a map of severity to count for the given findings.
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := map[Severity]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}
