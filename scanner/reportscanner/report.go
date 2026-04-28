package reportscanner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/auditscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/authscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/depscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/errorscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/httpinputscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/retentionscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/scriptscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/sqlscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/suppression"
	"github.com/shyshlakov/pci-dss-mcp/scanner/tlsscanner"
)

// ReportGenerator runs all scanners and produces a compliance report.
type ReportGenerator struct {
	scanners []scanner.Scanner
	db       *pcidb.DB
}

// NewReportGenerator creates a report generator with all 12 scanners.
func NewReportGenerator(db *pcidb.DB) *ReportGenerator {
	return &ReportGenerator{
		scanners: []scanner.Scanner{
			panscanner.New(),
			cryptoscanner.New(),
			tlsscanner.New(),
			errorscanner.New(),
			secretscanner.New(),
			authscanner.New(),
			auditscanner.New(),
			httpinputscanner.New(),
			retentionscanner.New(),
			sqlscanner.New(),
			scriptscanner.New(),
			depscanner.New(),
		},
		db: db,
	}
}

// fullScanner is implemented by scanners that support include_tests/include_untracked options.
type fullScanner interface {
	ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error)
}

// modeScanner is implemented by scanners that support scan mode selection (e.g., depscanner).
type modeScanner interface {
	ScanWithMode(ctx context.Context, targetPath string, mode string) (*scanner.ScanResult, error)
}

// taintCapableScanner is implemented by scanners that support flow-based
// severity adjustment via the internal/taint engine. In
// only panscanner implements this interface. /19 will extend
// coverage to errorscanner (ERR-LEAK) and panscanner's PAN-LOGGER rule.
type taintCapableScanner interface {
	ScanFullWithTaint(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool, includeTaint bool) (*scanner.ScanResult, error)
}

// Generate runs all scanners with PRODUCTION defaults: taint analysis ON
// for precision. Adds +2-30s to scan time depending on project size
// (go/packages.Load cost). Falls back to taint-OFF behavior via a single
// slog.Warn on taint engine load failure (missing go binary, air-gapped
// environment, broken module cache) — the existing GenerateWithOptions
// graceful-degradation path handles this. This is the canonical entry point
// for the MCP server, CLI wrappers, and any production/CI scan.
//
// Use GenerateFast() for dev iteration when speed matters more than
// precision (never in CI, audit, or production scans).
func (g *ReportGenerator) Generate(ctx context.Context, targetPath string) (*ComplianceReport, error) {
	return g.GenerateWithOptions(ctx, targetPath, "", false, true)
}

// GenerateFast runs the compliance report WITHOUT taint analysis.
// Opt-in for dev iteration when speed matters more than precision.
// Emits more HIGH/MEDIUM findings that would downgrade to INFO under taint
// (transit-only PAN-KEYWORD / PAN-TYPE for request/response DTOs).
// Never use in CI, audit, or production scans — prefer Generate().
func (g *ReportGenerator) GenerateFast(ctx context.Context, targetPath string) (*ComplianceReport, error) {
	return g.GenerateWithOptions(ctx, targetPath, "", false, false)
}

// reqFindings groups indices into the suppressionResults slice by active vs
// suppressed state. Used to derive per-requirement PASS/FAIL/SUPPRESSED
// status without re-scanning the flat results slice.
type reqFindings struct {
	active     []int
	suppressed []int
}

// GenerateWithOptions runs all scanners with configurable options and produces
// a compliance report. When includeTaint=true, scanners that implement
// taintCapableScanner are invoked with flow-based severity adjustment enabled
// (panscanner only). All other scanners use the standard fullScanner
// path unchanged. Default includeTaint=false: opt-in for accuracy vs
// speed (5-30s cost for packages.Load).
func (g *ReportGenerator) GenerateWithOptions(ctx context.Context, targetPath string, depScanMode string, includeTests bool, includeTaint bool) (*ComplianceReport, error) {
	startTime := time.Now()

	allFindings, findingScannerNames, totalFiles, totalLines := g.runAllScanners(ctx, targetPath, depScanMode, includeTests, includeTaint)

	allFindings, findingScannerNames = g.applyPackageExclusions(allFindings, findingScannerNames, targetPath)

	suppressionResults := suppression.ApplySuppression(allFindings, targetPath)

	coveredReqs := g.collectCoveredRequirements()
	reqMap := classifyFindingsByRequirement(suppressionResults)
	relatedReqPrimary := collectRelatedRequirementMap(suppressionResults)

	requirementStatus := g.buildRequirementStatus(coveredReqs, reqMap, suppressionResults)
	propagateCrossReferences(requirementStatus, relatedReqPrimary)
	addSBOMInventoryStatus(requirementStatus, targetPath)

	reportFindings, suppressions := buildReportFindings(g.db, suppressionResults, findingScannerNames)
	sort.SliceStable(reportFindings, func(i, j int) bool {
		return severityOrder(reportFindings[i].Severity) < severityOrder(reportFindings[j].Severity)
	})

	notChecked := g.buildNotCheckedEntries(requirementStatus)

	summary := buildReportSummary(reportFindings, requirementStatus)
	durationMS := time.Since(startTime).Milliseconds()

	report := &ComplianceReport{
		Metadata: ReportMetadata{
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
			TargetPath:   targetPath,
			TotalFiles:   totalFiles,
			TotalLines:   totalLines,
			DurationMS:   durationMS,
			ScannerCount: len(g.scanners),
		},
		Summary:           summary,
		RequirementStatus: requirementStatus,
		Findings:          reportFindings,
		Suppressions:      suppressions,
		NotChecked:        notChecked,
	}

	report.FindingsByRule = groupFindingsByRule(reportFindings)
	report.ScanSummary = buildScanSummary(reportFindings, totalFiles, durationMS)

	return report, nil
}

// runAllScanners invokes every registered scanner using the best interface it
// supports (taintCapable → packageContextAware → full → mode → plain). Returns
// the combined findings slice plus parallel scanner-name slice and aggregated
// file/line counts.
func (g *ReportGenerator) runAllScanners(ctx context.Context, targetPath, depScanMode string, includeTests, includeTaint bool) ([]scanner.Finding, []string, int, int) {
	var pkgCtx map[string]*keywords.PackageInfo
	var allFindings []scanner.Finding
	var findingScannerNames []string
	var totalFiles, totalLines int

	for _, s := range g.scanners {
		result, err := runSingleScanner(ctx, s, targetPath, depScanMode, includeTests, includeTaint, pkgCtx)
		if err != nil {
			slog.Error("scanner failed", "scanner", s.Name(), "error", err)
			continue
		}
		for _, f := range result.Findings {
			allFindings = append(allFindings, f)
			findingScannerNames = append(findingScannerNames, s.Name())
		}
		totalFiles += result.Metadata.ScannedFiles
		totalLines += result.Metadata.ScannedLines
	}
	return allFindings, findingScannerNames, totalFiles, totalLines
}

// runSingleScanner dispatches one scanner through the narrowest interface it
// implements. Taint-capable scanners get priority when includeTaint is true.
func runSingleScanner(ctx context.Context, s scanner.Scanner, targetPath, depScanMode string, includeTests, includeTaint bool, pkgCtx map[string]*keywords.PackageInfo) (*scanner.ScanResult, error) {
	if includeTaint {
		if tcs, ok := s.(taintCapableScanner); ok {
			return tcs.ScanFullWithTaint(ctx, targetPath, nil, includeTests, false, true)
		}
	}
	if pcs, ok := s.(scanner.PackageContextAwareScanner); ok {
		return pcs.ScanWithPackageContext(ctx, targetPath, nil, includeTests, false, pkgCtx)
	}
	if fs, ok := s.(fullScanner); ok {
		return fs.ScanFull(ctx, targetPath, nil, includeTests, false)
	}
	if ms, ok := s.(modeScanner); ok && depScanMode != "" {
		return ms.ScanWithMode(ctx, targetPath, depScanMode)
	}
	return s.Scan(ctx, targetPath)
}

// applyPackageExclusions drops findings that match any ExcludePackages pattern
// in .pci-dss-mcp-ignore and appends a SUPPRESSED-PACKAGE INFO finding per
// matched pattern so QSA auditors see what was deliberately scoped out.
func (g *ReportGenerator) applyPackageExclusions(findings []scanner.Finding, scannerNames []string, targetPath string) ([]scanner.Finding, []string) {
	parsedIgnore, parseErr := suppression.ParseIgnoreFileFull(filepath.Join(targetPath, ".pci-dss-mcp-ignore"))
	if parseErr != nil {
		slog.Warn("parse .pci-dss-mcp-ignore", "error", parseErr)
	}
	if parsedIgnore == nil || len(parsedIgnore.ExcludePackages) == 0 {
		return findings, scannerNames
	}

	filteredFindings, filteredNames, excludeReports := applyPackageExclusionsParallel(
		findings, scannerNames, targetPath, parsedIgnore.ExcludePackages)

	for _, rpt := range excludeReports {
		filteredFindings = append(filteredFindings, scanner.Finding{
			RuleID:        "SUPPRESSED-PACKAGE",
			Severity:      scanner.SeverityInfo,
			RequirementID: "n/a",
			FilePath:      rpt.Pattern,
			Line:          rpt.SourceLine,
			Description: fmt.Sprintf("Package pattern %q excluded by .pci-dss-mcp-ignore (dropped %d findings).",
				rpt.Pattern, rpt.MatchCount),
			Suggestion: "Verify exclusion is scoped correctly and does not hide in-scope payment code.",
		})
		filteredNames = append(filteredNames, "suppression")
	}
	return filteredFindings, filteredNames
}

// collectCoveredRequirements builds the set of requirement IDs covered by
// any registered scanner. Used later to decide NOT_CHECKED status.
func (g *ReportGenerator) collectCoveredRequirements() map[string]bool {
	coveredReqs := make(map[string]bool)
	for _, s := range g.scanners {
		for _, reqID := range s.Requirements() {
			coveredReqs[reqID] = true
		}
	}
	return coveredReqs
}

// classifyFindingsByRequirement groups suppression-result indices by their
// requirement ID, separating active from suppressed findings.
func classifyFindingsByRequirement(results []suppression.SuppressionResult) map[string]*reqFindings {
	reqMap := make(map[string]*reqFindings)
	for i, sr := range results {
		reqID := sr.Finding.RequirementID
		if reqMap[reqID] == nil {
			reqMap[reqID] = &reqFindings{}
		}
		if sr.Suppressed {
			reqMap[reqID].suppressed = append(reqMap[reqID].suppressed, i)
		} else {
			reqMap[reqID].active = append(reqMap[reqID].active, i)
		}
	}
	return reqMap
}

// collectRelatedRequirementMap returns a map from related-requirement ID to
// the primary requirement that produced the original finding. Used to
// propagate cross-mapping status to NOT_CHECKED requirements.
func collectRelatedRequirementMap(results []suppression.SuppressionResult) map[string]string {
	related := make(map[string]string)
	for _, sr := range results {
		if sr.Suppressed {
			continue
		}
		for _, relReq := range sr.Finding.RelatedRequirements {
			if _, exists := related[relReq]; !exists {
				related[relReq] = sr.Finding.RequirementID
			}
		}
	}
	return related
}

// buildRequirementStatus computes the PASS/FAIL/SUPPRESSED/NOT_CHECKED status
// map for every requirement in the database based on scanner coverage and
// active-vs-suppressed finding counts.
func (g *ReportGenerator) buildRequirementStatus(coveredReqs map[string]bool, reqMap map[string]*reqFindings, results []suppression.SuppressionResult) map[string]RequirementStatus {
	requirementStatus := make(map[string]RequirementStatus)
	for _, req := range g.db.All() {
		rs := RequirementStatus{
			RequirementID: req.RequirementID,
			Title:         req.Title,
		}

		if !coveredReqs[req.RequirementID] {
			rs.Status = "NOT_CHECKED"
			requirementStatus[req.RequirementID] = rs
			continue
		}

		rs.CoverageScope = req.CoverageScope
		rs.Limitations = req.Limitations
		rs.NotCovered = req.NotCovered

		rs = classifyRequirementFromFindings(rs, reqMap[req.RequirementID], results)
		requirementStatus[req.RequirementID] = rs
	}
	return requirementStatus
}

// classifyRequirementFromFindings produces a PASS/FAIL/SUPPRESSED status for
// a covered requirement given its grouped findings.
func classifyRequirementFromFindings(rs RequirementStatus, rf *reqFindings, results []suppression.SuppressionResult) RequirementStatus {
	if rf == nil {
		rs.Status = "PASS"
		return rs
	}
	hasActionable := false
	for _, idx := range rf.active {
		sev := results[idx].Finding.Severity
		if sev == scanner.SeverityCritical || sev == scanner.SeverityHigh || sev == scanner.SeverityMedium {
			hasActionable = true
			break
		}
	}
	switch {
	case hasActionable:
		rs.Status = "FAIL"
		rs.FindingCount = len(rf.active)
	case len(rf.active) == 0 && len(rf.suppressed) > 0:
		rs.Status = "SUPPRESSED"
		rs.FindingCount = len(rf.suppressed)
	default:
		rs.Status = "PASS"
	}
	return rs
}

// propagateCrossReferences copies PASS/FAIL status from a primary requirement
// to related NOT_CHECKED requirements that share a finding. NOT_CHECKED is the
// only status that gets overridden so directly-scanned requirements keep their
// own verdict.
func propagateCrossReferences(requirementStatus map[string]RequirementStatus, relatedReqPrimary map[string]string) {
	for relReqID, primaryReqID := range relatedReqPrimary {
		rs, exists := requirementStatus[relReqID]
		if !exists || rs.Status != "NOT_CHECKED" {
			continue
		}
		primaryRS, primaryExists := requirementStatus[primaryReqID]
		if !primaryExists {
			continue
		}
		rs.Status = primaryRS.Status
		rs.CrossReference = fmt.Sprintf("Covered by same finding (see %s)", primaryReqID)
		requirementStatus[relReqID] = rs
	}
}

// buildReportFindings splits suppression results into the active ReportFinding
// list and the SuppressionEntry list, enriching each with the owning scanner
// name and the requirement title from pcidb.
func buildReportFindings(db *pcidb.DB, results []suppression.SuppressionResult, scannerNames []string) ([]ReportFinding, []SuppressionEntry) {
	var reportFindings []ReportFinding
	var suppressions []SuppressionEntry
	for i, sr := range results {
		reqTitle := ""
		if req := db.Lookup(sr.Finding.RequirementID); req != nil {
			reqTitle = req.Title
		}
		rf := ReportFinding{
			Finding:          sr.Finding,
			RequirementTitle: reqTitle,
			ScannerName:      scannerNames[i],
		}
		if sr.Suppressed {
			suppressions = append(suppressions, SuppressionEntry{
				ReportFinding: rf,
				Reason:        sr.SuppressionReason,
				Source:        sr.SuppressionSource,
			})
			continue
		}
		reportFindings = append(reportFindings, rf)
	}
	return reportFindings, suppressions
}

// buildNotCheckedEntries produces pcidb-aware explanations for every
// NOT_CHECKED requirement, preferring parent-requirement cross-references,
// then explicit not-detectable reasons, then a generic QSA fallback.
func (g *ReportGenerator) buildNotCheckedEntries(requirementStatus map[string]RequirementStatus) []NotCheckedEntry {
	var notChecked []NotCheckedEntry
	for _, req := range g.db.All() {
		rs, ok := requirementStatus[req.RequirementID]
		if !ok || rs.Status != "NOT_CHECKED" {
			continue
		}
		entry := NotCheckedEntry{
			RequirementID: req.RequirementID,
			Title:         req.Title,
		}
		switch {
		case req.CoveredBy != "":
			parentTitle := req.CoveredBy
			if parentReq := g.db.Lookup(req.CoveredBy); parentReq != nil {
				parentTitle = parentReq.Title
			}
			entry.Explanation = fmt.Sprintf("Parent requirement %s (%s) partially covers this. Full verification requires QSA testing procedure %s.a", req.CoveredBy, parentTitle, req.RequirementID)
			entry.CoveredBy = req.CoveredBy
		case req.NotDetectableReason != "":
			entry.Explanation = req.NotDetectableReason
		default:
			entry.Explanation = fmt.Sprintf("%s -- requires manual review (QSA)", req.Title)
		}
		if req.TestingProcedure != "" {
			entry.TestingProcedure = req.TestingProcedure
		}
		notChecked = append(notChecked, entry)
	}
	return notChecked
}

// buildReportSummary counts PASS/FAIL/WARNING/SUPPRESSED/NOT_CHECKED states
// and collapses severity buckets for the top-level report summary.
func buildReportSummary(reportFindings []ReportFinding, requirementStatus map[string]RequirementStatus) ReportSummary {
	activeFindings := make([]scanner.Finding, len(reportFindings))
	for i, rf := range reportFindings {
		activeFindings[i] = rf.Finding
	}
	sevCounts := scanner.CountBySeverity(activeFindings)

	var passCount, failCount, warningCount, suppressedCount, notCheckedCount int
	for _, rs := range requirementStatus {
		switch rs.Status {
		case "PASS":
			passCount++
		case "FAIL":
			failCount++
		case "WARNING":
			warningCount++
		case "SUPPRESSED":
			suppressedCount++
		case "NOT_CHECKED":
			notCheckedCount++
		}
	}

	return ReportSummary{
		TotalRequirements: len(requirementStatus),
		Checked:           passCount + failCount + warningCount + suppressedCount,
		NotCheckedCount:   notCheckedCount,
		Pass:              passCount,
		Fail:              failCount,
		Warning:           warningCount,
		Suppressed:        suppressedCount,
		Critical:          sevCounts[scanner.SeverityCritical],
		High:              sevCounts[scanner.SeverityHigh],
		Medium:            sevCounts[scanner.SeverityMedium],
		Low:               sevCounts[scanner.SeverityLow],
		Info:              sevCounts[scanner.SeverityInfo],
	}
}

// severityOrder returns a sort key for severity (lower = more severe).
func severityOrder(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 0
	case scanner.SeverityHigh:
		return 1
	case scanner.SeverityMedium:
		return 2
	case scanner.SeverityLow:
		return 3
	case scanner.SeverityInfo:
		return 4
	default:
		return 5
	}
}

// severityOrderStr is like severityOrder but takes a string.
func severityOrderStr(s string) int {
	return severityOrder(scanner.Severity(s))
}

// groupFindingsByRule groups findings by rule_id, sorted by severity then count.
func groupFindingsByRule(findings []ReportFinding) []FindingsByRule {
	groups := make(map[string]*FindingsByRule)
	var order []string

	for _, f := range findings {
		key := f.RuleID
		if g, ok := groups[key]; ok {
			g.Count++
			g.Instances = append(g.Instances, f)
		} else {
			order = append(order, key)
			groups[key] = &FindingsByRule{
				RuleID:      f.RuleID,
				Severity:    string(f.Severity),
				Requirement: f.RequirementID,
				Count:       1,
				Instances:   []ReportFinding{f},
			}
		}
	}

	result := make([]FindingsByRule, 0, len(groups))
	for _, key := range order {
		result = append(result, *groups[key])
	}
	sort.SliceStable(result, func(i, j int) bool {
		si := severityOrderStr(result[i].Severity)
		sj := severityOrderStr(result[j].Severity)
		if si != sj {
			return si < sj
		}
		return result[i].Count > result[j].Count
	})
	return result
}

// buildScanSummary creates the AI-consumable summary.
func buildScanSummary(findings []ReportFinding, totalFiles int, durationMS int64) *ScanSummary {
	ss := &ScanSummary{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		ScannedFiles:  totalFiles,
		DurationMS:    durationMS,
	}

	for _, f := range findings {
		ss.BySeverity[string(f.Severity)]++
		ss.ByCategory[f.ScannerName]++
	}

	if len(findings) > 0 {
		ss.AITriageHint = "Run triage_findings for AI-assisted analysis of these findings"
	}

	return ss
}

// applyPackageExclusionsParallel filters findings AND the parallel
// findingScannerNames slice in lockstep using the exclude-package rules.
// Calls suppression.ApplyPackageExclusions to get the canonical filtered
// slice + audit reports, then walks the original findings once to keep the
// scanner-name parallel slice consistent.
func applyPackageExclusionsParallel(
	findings []scanner.Finding,
	scannerNames []string,
	projectRoot string,
	rules []suppression.ExcludePackageRule,
) ([]scanner.Finding, []string, []suppression.ExcludedPackageReport) {
	if len(rules) == 0 || len(findings) == 0 {
		return findings, scannerNames, nil
	}

	filteredFindings, reports := suppression.ApplyPackageExclusions(findings, projectRoot, rules)

	filteredNames := make([]string, 0, len(filteredFindings))
	for i, f := range findings {
		relPath := f.FilePath
		if filepath.IsAbs(f.FilePath) {
			if rel, err := filepath.Rel(projectRoot, f.FilePath); err == nil {
				relPath = rel
			}
		}
		excluded := false
		for _, r := range rules {
			if suppression.MatchExcludePackage(r.Pattern, relPath) {
				excluded = true
				break
			}
		}
		if !excluded && i < len(scannerNames) {
			filteredNames = append(filteredNames, scannerNames[i])
		}
	}

	return filteredFindings, filteredNames, reports
}
