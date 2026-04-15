package reportscanner

import (
	"fmt"
	"sort"
	"strings"
)

// requirementCategories maps PCI DSS top-level requirement numbers to titles.
var requirementCategories = map[string]string{
	"1":  "Install and Maintain Network Security Controls",
	"2":  "Apply Secure Configurations to All System Components",
	"3":  "Protect Stored Account Data",
	"4":  "Protect Cardholder Data with Strong Cryptography During Transmission",
	"5":  "Protect All Systems and Networks from Malicious Software",
	"6":  "Develop and Maintain Secure Systems and Software",
	"7":  "Restrict Access to System Components and Cardholder Data",
	"8":  "Identify Users and Authenticate Access",
	"9":  "Restrict Physical Access to Cardholder Data",
	"10": "Log and Monitor All Access to System Components and Cardholder Data",
	"11": "Test Security of Systems and Networks Regularly",
	"12": "Support Information Security with Organizational Policies and Programs",
}

// FormatHumanReadable produces a grouped text report from a ComplianceReport.
func FormatHumanReadable(report *ComplianceReport) string {
	var sb strings.Builder

	// Header.
	sb.WriteString(strings.Repeat("\u2501", 72))
	sb.WriteString("\n")
	sb.WriteString("PCI DSS v4.0.1 Compliance Report\n")
	fmt.Fprintf(&sb, "Target: %s\n", report.Metadata.TargetPath)
	fmt.Fprintf(&sb, "Generated: %s\n", report.Metadata.GeneratedAt)
	fmt.Fprintf(&sb, "Duration: %dms | Files: %d | Lines: %d\n",
		report.Metadata.DurationMS, report.Metadata.TotalFiles, report.Metadata.TotalLines)
	sb.WriteString(strings.Repeat("\u2501", 72))
	sb.WriteString("\n\n")

	// Severity summary.
	if report.Summary.Critical > 0 || report.Summary.High > 0 || report.Summary.Medium > 0 {
		fmt.Fprintf(&sb, "%d CRITICAL, %d HIGH, %d MEDIUM findings\n",
			report.Summary.Critical, report.Summary.High, report.Summary.Medium)
	} else {
		sb.WriteString("No active findings.\n")
	}
	if report.Summary.Low > 0 || report.Summary.Info > 0 {
		fmt.Fprintf(&sb, "(%d LOW, %d INFO informational findings not shown)\n",
			report.Summary.Low, report.Summary.Info)
	}
	if len(report.Suppressions) > 0 {
		fmt.Fprintf(&sb, "%d findings suppressed (see Suppression Audit below)\n",
			len(report.Suppressions))
	}
	sb.WriteString("\n")

	// Group findings by requirement category.
	catFindings := groupByCategory(report.Findings)
	catNums := sortedCategoryNumbers(catFindings)

	for _, catNum := range catNums {
		findings := catFindings[catNum]
		catTitle := requirementCategories[catNum]
		if catTitle == "" {
			catTitle = "Other"
		}

		// Sort within category: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO.
		sort.SliceStable(findings, func(i, j int) bool {
			return severityOrder(findings[i].Severity) < severityOrder(findings[j].Severity)
		})

		fmt.Fprintf(&sb, "--- Requirement %s: %s ---\n\n", catNum, catTitle)

		for _, f := range findings {
			fmt.Fprintf(&sb, "[%s] %s -- %s\n", f.Severity, f.RequirementID, f.RequirementTitle)
			fmt.Fprintf(&sb, "  %s:%d\n", f.FilePath, f.Line)
			fmt.Fprintf(&sb, "  %s\n", f.Description)
			fmt.Fprintf(&sb, "  Fix: %s\n", f.Suggestion)
			if len(f.RelatedRequirements) > 0 {
				fmt.Fprintf(&sb, "  Also satisfies: %s\n", strings.Join(f.RelatedRequirements, ", "))
			}
			sb.WriteString("\n")
		}
	}

	// Suppression audit section.
	if len(report.Suppressions) > 0 {
		sb.WriteString("--- Suppression Audit ---\n\n")
		for _, s := range report.Suppressions {
			fmt.Fprintf(&sb, "[SUPPRESSED] %s -- %s\n", s.RequirementID, s.RequirementTitle)
			fmt.Fprintf(&sb, "  %s:%d\n", s.FilePath, s.Line)
			fmt.Fprintf(&sb, "  %s\n", s.Description)
			fmt.Fprintf(&sb, "  Suppressed via: %s\n", s.Source)
			fmt.Fprintf(&sb, "  Reason: %s\n\n", s.Reason)
		}
	}

	// Footer.
	sb.WriteString(strings.Repeat("\u2501", 72))
	sb.WriteString("\n")
	sb.WriteString("Requirements Summary\n")
	fmt.Fprintf(&sb, "Checked: %d requirements | NOT_CHECKED: %d requirements (manual QSA verification required)\n",
		report.Summary.Checked, report.Summary.NotCheckedCount)
	fmt.Fprintf(&sb, "PASS: %d | FAIL: %d | WARNING: %d | SUPPRESSED: %d\n",
		report.Summary.Pass, report.Summary.Fail, report.Summary.Warning, report.Summary.Suppressed)

	if len(report.NotChecked) > 0 {
		sb.WriteString("\nNOT_CHECKED requirements (manual QSA verification required):\n")
		for _, nc := range report.NotChecked {
			if nc.CoveredBy != "" {
				fmt.Fprintf(&sb, "  %s: %s (partially covered by %s)\n", nc.RequirementID, nc.Title, nc.CoveredBy)
			} else {
				fmt.Fprintf(&sb, "  %s: %s\n", nc.RequirementID, nc.Title)
			}
		}
	}

	// Show accuracy notes for PASS requirements with coverage scope.
	var passWithScope []RequirementStatus
	for _, rs := range report.RequirementStatus {
		if rs.Status == "PASS" && rs.CoverageScope != "" {
			passWithScope = append(passWithScope, rs)
		}
	}
	if len(passWithScope) > 0 {
		// Sort for stable output.
		sort.SliceStable(passWithScope, func(i, j int) bool {
			return passWithScope[i].RequirementID < passWithScope[j].RequirementID
		})
		sb.WriteString("\nAccuracy Notes (PASS requirements):\n")
		for _, rs := range passWithScope {
			fmt.Fprintf(&sb, "  %s: Statically verified: %s", rs.RequirementID, rs.CoverageScope)
			if rs.NotCovered != "" {
				fmt.Fprintf(&sb, " Not verified: %s", rs.NotCovered)
			}
			sb.WriteString("\n")
		}
	}

	// Show cross-referenced requirements.
	var crossRefs []RequirementStatus
	for _, rs := range report.RequirementStatus {
		if rs.CrossReference != "" {
			crossRefs = append(crossRefs, rs)
		}
	}
	if len(crossRefs) > 0 {
		sort.SliceStable(crossRefs, func(i, j int) bool {
			return crossRefs[i].RequirementID < crossRefs[j].RequirementID
		})
		sb.WriteString("\nCross-Referenced Requirements:\n")
		for _, rs := range crossRefs {
			fmt.Fprintf(&sb, "  %s %s -- %s\n", rs.Status, rs.RequirementID, rs.CrossReference)
		}
	}

	sb.WriteString("\nNOTE: NOT_CHECKED != non-compliant. Static analysis cannot verify these controls.\nA Qualified Security Assessor (QSA) must review them.\n")
	sb.WriteString(strings.Repeat("\u2501", 72))
	sb.WriteString("\n")

	return sb.String()
}

// groupByCategory groups findings by their top-level requirement category number.
func groupByCategory(findings []ReportFinding) map[string][]ReportFinding {
	groups := make(map[string][]ReportFinding)
	for _, f := range findings {
		cat := extractCategory(f.RequirementID)
		groups[cat] = append(groups[cat], f)
	}
	return groups
}

// extractCategory returns the top-level requirement number from a requirement ID.
// "3.3.1" -> "3", "10.2.1" -> "10".
func extractCategory(reqID string) string {
	parts := strings.SplitN(reqID, ".", 2)
	return parts[0]
}

// sortedCategoryNumbers returns category numbers sorted numerically.
// Falls back to lexicographic order if either key is not a plain integer.
func sortedCategoryNumbers(groups map[string][]ReportFinding) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		var ni, nj int
		_, errI := fmt.Sscanf(keys[i], "%d", &ni)
		_, errJ := fmt.Sscanf(keys[j], "%d", &nj)
		if errI != nil || errJ != nil {
			return keys[i] < keys[j]
		}
		return ni < nj
	})
	return keys
}
