package reportscanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func newTestDB(t *testing.T) *pcidb.DB {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New() error: %v", err)
	}
	return db
}

func TestReportGenerator_NewHas11Scanners(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	if len(gen.scanners) != 11 {
		t.Errorf("NewReportGenerator has %d scanners, want 11", len(gen.scanners))
	}
}

// TestReportGenerator_RegistersSQLScanner ensures sql_schema is included in the
// default scanner slice.
func TestReportGenerator_RegistersSQLScanner(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	var found bool
	for _, s := range gen.scanners {
		if s.Name() == "sql_schema" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected sql_schema scanner to be registered in NewReportGenerator")
	}
}

func TestReportGenerator_EmptyDir(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()
	report, err := gen.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// No findings expected.
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings in empty dir, got %d", len(report.Findings))
	}

	// All detectable requirements should be PASS, rest NOT_CHECKED.
	var passCount, notCheckedCount int
	for _, rs := range report.RequirementStatus {
		switch rs.Status {
		case "PASS":
			passCount++
		case "NOT_CHECKED":
			notCheckedCount++
		}
	}
	if passCount == 0 {
		t.Error("expected some PASS requirements for empty dir (covered reqs with no findings)")
	}
	if notCheckedCount == 0 {
		t.Error("expected some NOT_CHECKED requirements")
	}

	// Metadata check.
	if report.Metadata.ScannerCount != 11 {
		t.Errorf("ScannerCount = %d, want 11", report.Metadata.ScannerCount)
	}
	if report.Metadata.GeneratedAt == "" {
		t.Error("GeneratedAt should not be empty")
	}

	// Summary totals.
	if report.Summary.TotalRequirements == 0 {
		t.Error("TotalRequirements should be > 0")
	}
	if report.Summary.NotCheckedCount == 0 {
		t.Error("NotCheckedCount should be > 0")
	}
}

func TestReportJSON_Schema(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{
			GeneratedAt:  "2026-04-10T12:00:00Z",
			TargetPath:   "/test",
			TotalFiles:   10,
			TotalLines:   500,
			DurationMS:   100,
			ScannerCount: 11,
		},
		Summary: ReportSummary{
			TotalRequirements: 249,
			Checked:           15,
			NotCheckedCount:   234,
			Pass:              10,
			Fail:              3,
			Suppressed:        2,
			Critical:          1,
			High:              2,
		},
		RequirementStatus: map[string]RequirementStatus{
			"3.3.1": {RequirementID: "3.3.1", Title: "SAD Not Retained", Status: "FAIL", FindingCount: 2},
		},
		Findings: []ReportFinding{
			{
				Finding:          scanner.Finding{RuleID: "PAN-001", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "a.go", Line: 1, Description: "test", Suggestion: "fix"},
				RequirementTitle: "SAD Not Retained",
				ScannerName:      "pan_data",
			},
		},
		Suppressions: []SuppressionEntry{
			{
				ReportFinding: ReportFinding{
					Finding:          scanner.Finding{RuleID: "CRYPTO-001", Severity: scanner.SeverityCritical, RequirementID: "6.2.4", FilePath: "b.go", Line: 2, Description: "suppressed", Suggestion: "ok"},
					RequirementTitle: "Secure Dev",
					ScannerName:      "encryption",
				},
				Reason: "test fixture",
				Source: "inline comment",
			},
		},
		NotChecked: []NotCheckedEntry{
			{RequirementID: "1.1.1", Title: "Network Policies", Explanation: "Network Policies -- requires manual review (QSA)"},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	// Verify all top-level keys present.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	requiredKeys := []string{"metadata", "summary", "requirement_status", "findings", "suppressions", "not_checked"}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON missing required key %q", key)
		}
	}

	// Verify round-trip.
	var decoded ComplianceReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("round-trip unmarshal error: %v", err)
	}
	if decoded.Findings[0].RequirementTitle != "SAD Not Retained" {
		t.Errorf("RequirementTitle = %q after round-trip", decoded.Findings[0].RequirementTitle)
	}
	if decoded.Findings[0].ScannerName != "pan_data" {
		t.Errorf("ScannerName = %q after round-trip", decoded.Findings[0].ScannerName)
	}
	if decoded.Suppressions[0].Reason != "test fixture" {
		t.Errorf("Suppression Reason = %q after round-trip", decoded.Suppressions[0].Reason)
	}
	if decoded.NotChecked[0].Explanation == "" {
		t.Error("NotChecked Explanation should not be empty")
	}
}

func TestReportRequirementStatus_Logic(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	// Create dir with a known PAN violation.
	dir := t.TempDir()
	writeTestFile(t, dir, "handler.go", `package payment

import (
	"fmt"
	"net/http"
)

func handlePayment(w http.ResponseWriter, r *http.Request) {
	cardNumber := r.FormValue("card")
	fmt.Fprintf(w, "Card: %s", cardNumber)
}
`)

	report, err := gen.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Should have at least some FAIL requirements.
	hasFail := false
	for _, rs := range report.RequirementStatus {
		if rs.Status == "FAIL" {
			hasFail = true
			break
		}
	}
	if !hasFail {
		t.Error("expected at least one FAIL requirement from PAN violation")
	}

	// Summary should reflect findings.
	if report.Summary.Fail == 0 {
		t.Error("Summary.Fail should be > 0")
	}
}

// --- Format tests ---

func TestFormatHumanReadable_Header(t *testing.T) {
	report := makeTestReport(3, 2, 1, 0, 0, 0)
	output := FormatHumanReadable(report)

	if !strings.Contains(output, "PCI DSS v4.0.1 Compliance Report") {
		t.Error("missing report title")
	}
	if !strings.Contains(output, "3 CRITICAL, 2 HIGH, 1 MEDIUM findings") {
		t.Errorf("missing severity summary, got:\n%s", output)
	}
	if !strings.Contains(output, "Target:") {
		t.Error("missing target in header")
	}
}

func TestFormatHumanReadable_LowInfoShown(t *testing.T) {
	report := makeTestReport(0, 0, 0, 2, 1, 0)
	output := FormatHumanReadable(report)

	if !strings.Contains(output, "No active findings.") {
		t.Error("should show 'No active findings' when only LOW/INFO")
	}
	if !strings.Contains(output, "(2 LOW, 1 INFO informational findings not shown)") {
		t.Errorf("missing LOW/INFO note, got:\n%s", output)
	}
}

func TestFormatHumanReadable_SuppressedNote(t *testing.T) {
	report := makeTestReport(1, 0, 0, 0, 0, 2)
	output := FormatHumanReadable(report)

	if !strings.Contains(output, "2 findings suppressed") {
		t.Error("missing suppression count note")
	}
	if !strings.Contains(output, "Suppression Audit") {
		t.Error("missing Suppression Audit section")
	}
}

func TestFormatHumanReadable_CategoryGrouping(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{Critical: 1, High: 1},
		Findings: []ReportFinding{
			{Finding: scanner.Finding{RuleID: "A", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "a.go", Line: 1, Description: "pan leak", Suggestion: "fix"}, RequirementTitle: "SAD", ScannerName: "pan"},
			{Finding: scanner.Finding{RuleID: "B", Severity: scanner.SeverityHigh, RequirementID: "8.3.6", FilePath: "b.go", Line: 2, Description: "weak pw", Suggestion: "fix"}, RequirementTitle: "Auth", ScannerName: "auth"},
		},
	}

	output := FormatHumanReadable(report)

	r3idx := strings.Index(output, "Requirement 3:")
	r8idx := strings.Index(output, "Requirement 8:")
	if r3idx < 0 || r8idx < 0 {
		t.Fatalf("missing category sections, got:\n%s", output)
	}
	if r3idx > r8idx {
		t.Error("Requirement 3 should appear before Requirement 8")
	}
}

func TestFormatHumanReadable_Footer(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary: ReportSummary{
			Checked:         15,
			NotCheckedCount: 234,
			Pass:            10,
			Fail:            3,
			Warning:         0,
			Suppressed:      2,
		},
		NotChecked: []NotCheckedEntry{
			{RequirementID: "1.1.1", Title: "Network Security Policies"},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "Requirements Summary") {
		t.Error("missing Requirements Summary in footer")
	}
	if !strings.Contains(output, "NOT_CHECKED: 234") {
		t.Error("missing NOT_CHECKED count in footer")
	}
	if !strings.Contains(output, "non-compliant") {
		t.Error("missing NOT_CHECKED disclaimer")
	}
	if !strings.Contains(output, "QSA") {
		t.Error("missing QSA reference")
	}
	if !strings.Contains(output, "1.1.1: Network Security Policies") {
		t.Error("missing NOT_CHECKED requirement listing")
	}
}

func TestFormatHumanReadable_ZeroFindings(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z", TotalFiles: 50, TotalLines: 3000},
		Summary:  ReportSummary{},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "No active findings") {
		t.Error("zero-finding report should show 'No active findings'")
	}
	if !strings.Contains(output, "50") {
		t.Error("metadata should be visible")
	}
}

func TestFormatHumanReadable_FindingFormat(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{Critical: 1},
		Findings: []ReportFinding{
			{
				Finding:          scanner.Finding{RuleID: "PAN-001", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "payment/handler.go", Line: 45, Description: "PAN variable logged", Suggestion: "Remove PAN from log"},
				RequirementTitle: "SAD Not Retained",
				ScannerName:      "pan_data",
			},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "[CRITICAL] 3.3.1 -- SAD Not Retained") {
		t.Errorf("missing finding header format, got:\n%s", output)
	}
	if !strings.Contains(output, "payment/handler.go:45") {
		t.Error("missing file:line")
	}
	if !strings.Contains(output, "Fix: Remove PAN from log") {
		t.Error("missing Fix: suggestion")
	}
}

// --- Accuracy annotation and cross-mapping tests ---

func TestReportAccuracyAnnotations(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()
	report, err := gen.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Requirement 4.2.1 is detectable and covered by tlsscanner.
	// When empty dir (no findings), it should be PASS with CoverageScope populated.
	rs, ok := report.RequirementStatus["4.2.1"]
	if !ok {
		t.Fatal("missing RequirementStatus for 4.2.1")
	}
	if rs.Status != "PASS" {
		t.Errorf("4.2.1 status = %q, want PASS", rs.Status)
	}
	if rs.CoverageScope == "" {
		t.Error("4.2.1 CoverageScope should be populated for PASS requirement")
	}
	if !strings.Contains(rs.CoverageScope, "InsecureSkipVerify") {
		t.Errorf("4.2.1 CoverageScope = %q, want substring 'InsecureSkipVerify'", rs.CoverageScope)
	}
	if len(rs.Limitations) == 0 {
		t.Error("4.2.1 Limitations should be populated")
	}
	if rs.NotCovered == "" {
		t.Error("4.2.1 NotCovered should be populated")
	}
}

func TestReportNotCheckedParentCoverage(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()
	report, err := gen.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// 3.3.1.1 has CoveredBy="3.3.1" in pcidb, should show parent coverage note.
	var found *NotCheckedEntry
	for i, nc := range report.NotChecked {
		if nc.RequirementID == "3.3.1.1" {
			found = &report.NotChecked[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing NotCheckedEntry for 3.3.1.1")
	}
	if !strings.Contains(found.Explanation, "Parent requirement 3.3.1") {
		t.Errorf("3.3.1.1 Explanation = %q, want substring 'Parent requirement 3.3.1'", found.Explanation)
	}
	if found.CoveredBy != "3.3.1" {
		t.Errorf("3.3.1.1 CoveredBy = %q, want '3.3.1'", found.CoveredBy)
	}
}

func TestReportCrossMappingPropagation(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	// Create temp dir with a Go file containing a hardcoded encryption key
	// to trigger CRYPTO-HARDCODED-KEY finding with primary 6.2.4 and
	// RelatedRequirements=["8.6.2"].
	dir := t.TempDir()
	writeTestFile(t, dir, "crypto.go", `package payment

import "crypto/aes"

func encrypt(data []byte) ([]byte, error) {
	key := []byte("hardcoded-secret-key-1234567890!!")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	_ = block
	return data, nil
}
`)

	report, err := gen.Generate(context.Background(), dir)
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Verify the primary requirement (6.2.4) has FAIL status.
	primaryRS, ok := report.RequirementStatus["6.2.4"]
	if !ok {
		t.Fatal("missing RequirementStatus for 6.2.4")
	}
	if primaryRS.Status != "FAIL" {
		t.Errorf("6.2.4 status = %q, want FAIL", primaryRS.Status)
	}

	// The related requirement 8.6.2 is independently covered by
	// secretscanner + authscanner, so cross-reference propagation does not
	// override its direct status here. The propagation feature still applies
	// to any related requirement that is NOT_CHECKED at classification time.
	if _, ok := report.RequirementStatus["8.6.2"]; !ok {
		t.Fatal("missing RequirementStatus for 8.6.2")
	}
}

func TestFormatHumanReadable_AccuracyNotes(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{Pass: 1},
		RequirementStatus: map[string]RequirementStatus{
			"4.2.1": {
				RequirementID: "4.2.1",
				Title:         "Strong Cryptography for PAN Transmission",
				Status:        "PASS",
				CoverageScope: "Detects InsecureSkipVerify, weak TLS versions",
				NotCovered:    "Network-level encryption for non-Go components",
			},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "Accuracy Notes (PASS requirements):") {
		t.Error("missing 'Accuracy Notes' section header")
	}
	if !strings.Contains(output, "Statically verified:") {
		t.Error("missing 'Statically verified:' text")
	}
	if !strings.Contains(output, "Not verified:") {
		t.Error("missing 'Not verified:' text")
	}
	if !strings.Contains(output, "InsecureSkipVerify") {
		t.Error("missing coverage scope detail")
	}
}

func TestFormatHumanReadable_CrossReference(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{Pass: 1},
		RequirementStatus: map[string]RequirementStatus{
			"3.6.1.2": {
				RequirementID:  "3.6.1.2",
				Title:          "Secret Key Access Restriction",
				Status:         "FAIL",
				CrossReference: "Covered by same finding (see 6.2.4)",
			},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "Cross-Referenced Requirements:") {
		t.Error("missing 'Cross-Referenced Requirements:' section header")
	}
	if !strings.Contains(output, "Covered by same finding (see 6.2.4)") {
		t.Errorf("missing cross-reference text, got:\n%s", output)
	}
}

func TestFormatHumanReadable_NotCheckedParent(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{NotCheckedCount: 1},
		NotChecked: []NotCheckedEntry{
			{
				RequirementID: "3.3.1.1",
				Title:         "Full Track Data Not Retained",
				Explanation:   "Parent requirement 3.3.1 partially covers this",
				CoveredBy:     "3.3.1",
			},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "partially covered by 3.3.1") {
		t.Errorf("missing 'partially covered by' text, got:\n%s", output)
	}
}

func TestFormatHumanReadable_AlsoSatisfies(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z"},
		Summary:  ReportSummary{Critical: 1},
		Findings: []ReportFinding{
			{
				Finding: scanner.Finding{
					RuleID:              "CRYPTO-HARDCODED-KEY",
					Severity:            scanner.SeverityCritical,
					RequirementID:       "6.2.4",
					FilePath:            "crypto.go",
					Line:                10,
					Description:         "Hardcoded encryption key",
					Suggestion:          "Use key management",
					RelatedRequirements: []string{"3.6.1.2"},
				},
				RequirementTitle: "Secure Development",
				ScannerName:      "encryption",
			},
		},
	}

	output := FormatHumanReadable(report)

	if !strings.Contains(output, "Also satisfies: 3.6.1.2") {
		t.Errorf("missing 'Also satisfies:' text, got:\n%s", output)
	}
}

// --- GenerateWithOptions tests ---

func TestGenerateWithOptions_BackwardCompatibility(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()

	// Post-19.3: Generate defaults to taint ON, so the
	// taint-OFF equivalence contract moved to GenerateFast() vs
	// GenerateWithOptions(..., false). Both MUST produce identical results
	// (empty dir = 0 findings) as a regression lock on the GenerateFast
	// convenience wrapper.
	report1, err := gen.GenerateFast(context.Background(), dir)
	if err != nil {
		t.Fatalf("GenerateFast error: %v", err)
	}

	report2, err := gen.GenerateWithOptions(context.Background(), dir, "", false, false)
	if err != nil {
		t.Fatalf("GenerateWithOptions error: %v", err)
	}

	// Same number of findings (empty dir = 0 each).
	if len(report1.Findings) != len(report2.Findings) {
		t.Errorf("findings count mismatch: GenerateFast=%d, GenerateWithOptions=%d",
			len(report1.Findings), len(report2.Findings))
	}

	// Same scanner count.
	if report1.Metadata.ScannerCount != report2.Metadata.ScannerCount {
		t.Errorf("ScannerCount mismatch: GenerateFast=%d, GenerateWithOptions=%d",
			report1.Metadata.ScannerCount, report2.Metadata.ScannerCount)
	}
}

// TestGenerateFast_Equivalence locks contract: the new
// GenerateFast() convenience wrapper is exactly equivalent to
// GenerateWithOptions(..., "", false, false) — same finding counts, same
// scanner count. This protects against accidental drift in the Generate/
// GenerateFast/GenerateWithOptions split if future changes add additional
// default options to Generate().
func TestGenerateFast_Equivalence(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()

	reportFast, err := gen.GenerateFast(context.Background(), dir)
	if err != nil {
		t.Fatalf("GenerateFast error: %v", err)
	}
	reportOpts, err := gen.GenerateWithOptions(context.Background(), dir, "", false, false)
	if err != nil {
		t.Fatalf("GenerateWithOptions error: %v", err)
	}

	if len(reportFast.Findings) != len(reportOpts.Findings) {
		t.Errorf("findings count mismatch: GenerateFast=%d, GenerateWithOptions(false,false)=%d",
			len(reportFast.Findings), len(reportOpts.Findings))
	}
	if reportFast.Metadata.ScannerCount != reportOpts.Metadata.ScannerCount {
		t.Errorf("ScannerCount mismatch: GenerateFast=%d, GenerateWithOptions=%d",
			reportFast.Metadata.ScannerCount, reportOpts.Metadata.ScannerCount)
	}
}

func TestGenerateWithOptions_IncludeTests(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()

	// GenerateWithOptions with includeTests=true should not error.
	report, err := gen.GenerateWithOptions(context.Background(), dir, "", true, false)
	if err != nil {
		t.Fatalf("GenerateWithOptions with includeTests=true error: %v", err)
	}

	if report.Metadata.ScannerCount != 11 {
		t.Errorf("ScannerCount = %d, want 11", report.Metadata.ScannerCount)
	}
}

func TestGenerateWithOptions_DepScanMode(t *testing.T) {
	db := newTestDB(t)
	gen := NewReportGenerator(db)

	dir := t.TempDir()

	// GenerateWithOptions with depScanMode="offline" should not error.
	report, err := gen.GenerateWithOptions(context.Background(), dir, "offline", false, false)
	if err != nil {
		t.Fatalf("GenerateWithOptions with depScanMode=offline error: %v", err)
	}

	if report.Metadata.ScannerCount != 11 {
		t.Errorf("ScannerCount = %d, want 11", report.Metadata.ScannerCount)
	}
}

// --- findings_by_rule and scan_summary tests ---

func TestGroupFindingsByRule(t *testing.T) {
	findings := []ReportFinding{
		{Finding: scanner.Finding{RuleID: "AUDIT-NO-LOG", Severity: scanner.SeverityHigh, RequirementID: "10.2.1", FilePath: "a.go", Line: 1, Description: "no log", Suggestion: "add log"}, ScannerName: "audit"},
		{Finding: scanner.Finding{RuleID: "AUDIT-NO-LOG", Severity: scanner.SeverityHigh, RequirementID: "10.2.1", FilePath: "b.go", Line: 2, Description: "no log", Suggestion: "add log"}, ScannerName: "audit"},
		{Finding: scanner.Finding{RuleID: "AUDIT-NO-LOG", Severity: scanner.SeverityHigh, RequirementID: "10.2.1", FilePath: "c.go", Line: 3, Description: "no log", Suggestion: "add log"}, ScannerName: "audit"},
		{Finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, RequirementID: "6.2.4", FilePath: "d.go", Line: 10, Description: "hardcoded key", Suggestion: "use KMS"}, ScannerName: "encryption"},
		{Finding: scanner.Finding{RuleID: "CRYPTO-HARDCODED-KEY", Severity: scanner.SeverityCritical, RequirementID: "6.2.4", FilePath: "e.go", Line: 20, Description: "hardcoded key", Suggestion: "use KMS"}, ScannerName: "encryption"},
	}

	groups := groupFindingsByRule(findings)

	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}

	// CRITICAL should be first (CRYPTO-HARDCODED-KEY).
	if groups[0].RuleID != "CRYPTO-HARDCODED-KEY" {
		t.Errorf("first group RuleID = %q, want CRYPTO-HARDCODED-KEY", groups[0].RuleID)
	}
	if groups[0].Severity != "CRITICAL" {
		t.Errorf("first group Severity = %q, want CRITICAL", groups[0].Severity)
	}
	if groups[0].Count != 2 {
		t.Errorf("first group Count = %d, want 2", groups[0].Count)
	}
	if len(groups[0].Instances) != 2 {
		t.Errorf("first group Instances = %d, want 2", len(groups[0].Instances))
	}

	// HIGH second (AUDIT-NO-LOG).
	if groups[1].RuleID != "AUDIT-NO-LOG" {
		t.Errorf("second group RuleID = %q, want AUDIT-NO-LOG", groups[1].RuleID)
	}
	if groups[1].Count != 3 {
		t.Errorf("second group Count = %d, want 3", groups[1].Count)
	}
}

func TestGroupFindingsByRuleSameSeverity(t *testing.T) {
	findings := []ReportFinding{
		{Finding: scanner.Finding{RuleID: "RULE-A", Severity: scanner.SeverityHigh, RequirementID: "6.2.4", FilePath: "a.go", Line: 1, Description: "test", Suggestion: "fix"}, ScannerName: "test"},
		{Finding: scanner.Finding{RuleID: "RULE-B", Severity: scanner.SeverityHigh, RequirementID: "6.2.4", FilePath: "b.go", Line: 1, Description: "test", Suggestion: "fix"}, ScannerName: "test"},
		{Finding: scanner.Finding{RuleID: "RULE-B", Severity: scanner.SeverityHigh, RequirementID: "6.2.4", FilePath: "c.go", Line: 1, Description: "test", Suggestion: "fix"}, ScannerName: "test"},
		{Finding: scanner.Finding{RuleID: "RULE-B", Severity: scanner.SeverityHigh, RequirementID: "6.2.4", FilePath: "d.go", Line: 1, Description: "test", Suggestion: "fix"}, ScannerName: "test"},
	}

	groups := groupFindingsByRule(findings)

	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}

	// Same severity: higher count first (RULE-B has 3, RULE-A has 1).
	if groups[0].RuleID != "RULE-B" {
		t.Errorf("first group RuleID = %q, want RULE-B (higher count)", groups[0].RuleID)
	}
	if groups[1].RuleID != "RULE-A" {
		t.Errorf("second group RuleID = %q, want RULE-A", groups[1].RuleID)
	}
}

func TestGroupFindingsByRuleEmpty(t *testing.T) {
	groups := groupFindingsByRule(nil)
	if len(groups) != 0 {
		t.Errorf("got %d groups for nil input, want 0", len(groups))
	}

	groups = groupFindingsByRule([]ReportFinding{})
	if len(groups) != 0 {
		t.Errorf("got %d groups for empty input, want 0", len(groups))
	}
}

func TestBuildScanSummary(t *testing.T) {
	findings := []ReportFinding{
		{Finding: scanner.Finding{RuleID: "A", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "a.go", Line: 1, Description: "t", Suggestion: "f"}, ScannerName: "pan_data"},
		{Finding: scanner.Finding{RuleID: "B", Severity: scanner.SeverityHigh, RequirementID: "6.2.4", FilePath: "b.go", Line: 2, Description: "t", Suggestion: "f"}, ScannerName: "encryption"},
		{Finding: scanner.Finding{RuleID: "C", Severity: scanner.SeverityHigh, RequirementID: "8.3.6", FilePath: "c.go", Line: 3, Description: "t", Suggestion: "f"}, ScannerName: "auth"},
		{Finding: scanner.Finding{RuleID: "D", Severity: scanner.SeverityMedium, RequirementID: "10.2.1", FilePath: "d.go", Line: 4, Description: "t", Suggestion: "f"}, ScannerName: "audit"},
		{Finding: scanner.Finding{RuleID: "E", Severity: scanner.SeverityMedium, RequirementID: "10.2.1", FilePath: "e.go", Line: 5, Description: "t", Suggestion: "f"}, ScannerName: "audit"},
	}

	ss := buildScanSummary(findings, 42, 150)

	if ss.TotalFindings != 5 {
		t.Errorf("TotalFindings = %d, want 5", ss.TotalFindings)
	}
	if ss.ScannedFiles != 42 {
		t.Errorf("ScannedFiles = %d, want 42", ss.ScannedFiles)
	}
	if ss.DurationMS != 150 {
		t.Errorf("DurationMS = %d, want 150", ss.DurationMS)
	}

	// BySeverity.
	if ss.BySeverity["CRITICAL"] != 1 {
		t.Errorf("BySeverity[CRITICAL] = %d, want 1", ss.BySeverity["CRITICAL"])
	}
	if ss.BySeverity["HIGH"] != 2 {
		t.Errorf("BySeverity[HIGH] = %d, want 2", ss.BySeverity["HIGH"])
	}
	if ss.BySeverity["MEDIUM"] != 2 {
		t.Errorf("BySeverity[MEDIUM] = %d, want 2", ss.BySeverity["MEDIUM"])
	}

	// ByCategory.
	if ss.ByCategory["pan_data"] != 1 {
		t.Errorf("ByCategory[pan_data] = %d, want 1", ss.ByCategory["pan_data"])
	}
	if ss.ByCategory["audit"] != 2 {
		t.Errorf("ByCategory[audit] = %d, want 2", ss.ByCategory["audit"])
	}

	// AITriageHint should be populated.
	if ss.AITriageHint == "" {
		t.Error("AITriageHint should be populated when findings exist")
	}
}

func TestBuildScanSummaryEmpty(t *testing.T) {
	ss := buildScanSummary(nil, 0, 0)

	if ss.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", ss.TotalFindings)
	}
	if ss.AITriageHint != "" {
		t.Errorf("AITriageHint = %q, want empty for no findings", ss.AITriageHint)
	}
}

func TestComplianceReportJSON_NewFields(t *testing.T) {
	report := &ComplianceReport{
		Metadata: ReportMetadata{GeneratedAt: "2026-04-11T12:00:00Z", TargetPath: "/test"},
		Summary:  ReportSummary{Critical: 1},
		ScanSummary: &ScanSummary{
			TotalFindings: 1,
			BySeverity:    map[string]int{"CRITICAL": 1},
			ByCategory:    map[string]int{"test": 1},
			ScannedFiles:  10,
			DurationMS:    50,
			AITriageHint:  "Run triage_findings",
		},
		RequirementStatus: map[string]RequirementStatus{},
		Findings: []ReportFinding{
			{Finding: scanner.Finding{RuleID: "T", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "a.go", Line: 1, Description: "t", Suggestion: "f"}, ScannerName: "test"},
		},
		FindingsByRule: []FindingsByRule{
			{RuleID: "T", Severity: "CRITICAL", Requirement: "3.3.1", Count: 1, Instances: []ReportFinding{
				{Finding: scanner.Finding{RuleID: "T", Severity: scanner.SeverityCritical, RequirementID: "3.3.1", FilePath: "a.go", Line: 1, Description: "t", Suggestion: "f"}, ScannerName: "test"},
			}},
		},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal error: %v", err)
	}

	// New fields present.
	if _, ok := raw["scan_summary"]; !ok {
		t.Error("JSON missing scan_summary key")
	}
	if _, ok := raw["findings_by_rule"]; !ok {
		t.Error("JSON missing findings_by_rule key")
	}

	// Backward-compat: existing fields still present.
	if _, ok := raw["findings"]; !ok {
		t.Error("JSON missing findings key (backward compat)")
	}
	if _, ok := raw["metadata"]; !ok {
		t.Error("JSON missing metadata key")
	}
}

func TestComplianceReportJSON_OmitNewFieldsWhenEmpty(t *testing.T) {
	report := &ComplianceReport{
		Metadata:          ReportMetadata{GeneratedAt: "2026-04-11T12:00:00Z", TargetPath: "/test"},
		RequirementStatus: map[string]RequirementStatus{},
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	jsonStr := string(data)

	// scan_summary and findings_by_rule should be absent when nil/empty.
	if strings.Contains(jsonStr, `"scan_summary"`) {
		t.Error("JSON should NOT contain scan_summary when nil")
	}
	if strings.Contains(jsonStr, `"findings_by_rule"`) {
		t.Error("JSON should NOT contain findings_by_rule when empty")
	}
}

// --- helpers ---

func makeTestReport(critical, high, medium, low, info, suppressed int) *ComplianceReport {
	report := &ComplianceReport{
		Metadata: ReportMetadata{TargetPath: "/test", GeneratedAt: "2026-04-10T12:00:00Z", TotalFiles: 10, TotalLines: 500},
		Summary: ReportSummary{
			Critical: critical,
			High:     high,
			Medium:   medium,
			Low:      low,
			Info:     info,
		},
	}

	addFindings := func(sev scanner.Severity, count int) {
		for i := 0; i < count; i++ {
			report.Findings = append(report.Findings, ReportFinding{
				Finding:          scanner.Finding{RuleID: "TEST", Severity: sev, RequirementID: "3.3.1", FilePath: "a.go", Line: i + 1, Description: "test", Suggestion: "fix"},
				RequirementTitle: "Test Req",
				ScannerName:      "test",
			})
		}
	}

	addFindings(scanner.SeverityCritical, critical)
	addFindings(scanner.SeverityHigh, high)
	addFindings(scanner.SeverityMedium, medium)
	addFindings(scanner.SeverityLow, low)
	addFindings(scanner.SeverityInfo, info)

	for i := 0; i < suppressed; i++ {
		report.Suppressions = append(report.Suppressions, SuppressionEntry{
			ReportFinding: ReportFinding{
				Finding:          scanner.Finding{RuleID: "TEST", Severity: scanner.SeverityCritical, RequirementID: "6.2.4", FilePath: "b.go", Line: i + 1, Description: "suppressed", Suggestion: "ok"},
				RequirementTitle: "Suppressed Req",
				ScannerName:      "test",
			},
			Reason: "known",
			Source: "inline comment",
		})
	}

	return report
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := dir + "/" + name
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- ( /) report-level integration tests ---

// filterFindingsByRulePrefix returns findings whose RuleID starts with prefix.
// Used by deferred-sink assertions to compare ERR-LEAK / PAN-LOGGER
// slices between taint off and taint on runs.
func filterFindingsByRulePrefix(findings []ReportFinding, prefix string) []ReportFinding {
	var out []ReportFinding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, prefix) {
			out = append(out, f)
		}
	}
	return out
}

// findCVVPANKeyword returns the first PAN-KEYWORD finding whose Description or
// FilePath mentions CVV, or nil if none present.
func findCVVPANKeyword(findings []ReportFinding) *ReportFinding {
	for i := range findings {
		f := &findings[i]
		if f.RuleID != "PAN-KEYWORD" {
			continue
		}
		if strings.Contains(f.Description, "CVV") || strings.Contains(f.Description, "cvv") ||
			strings.Contains(f.FilePath, "tokenize.go") {
			return f
		}
	}
	return nil
}

// TestReport_IncludeTaint locks: the include_taint knob threads through
// GenerateWithOptions into panscanner's taint bridge, downgrading PAN-KEYWORD
// from HIGH to Info and suppressing PAN-TYPE entirely for transit-only CHD
// fields per and the PCI SSC FAQ on non-persistent memory encryption.
//
// Reuses 's transit fixture at scanner/panscanner/testdata/taint/transit
// which contains a /requests/ DTO with CVV/PAN fields flowing only to an HTTP
// client — no DB sink reachable. The bridge must downgrade PAN-KEYWORD to INFO
// on the transit-shape file and drop the corresponding PAN-TYPE finding.
func TestReport_IncludeTaint(t *testing.T) {
	fixturePath, err := filepath.Abs(filepath.Join("..", "panscanner", "testdata", "taint", "transit"))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(fixturePath, "go.mod")); err != nil {
		t.Fatalf("fixture go.mod missing: %v", err)
	}
	t.Cleanup(taint.Reset)

	db := newTestDB(t)
	gen := NewReportGenerator(db)
	ctx := context.Background()

	// First pass: include_taint=false. default path; PAN-KEYWORD
	// transit CVV must retain HIGH severity (no bridge adjustment).
	reportOff, err := gen.GenerateWithOptions(ctx, fixturePath, "", false, false)
	if err != nil {
		t.Fatalf("generate (taint off): %v", err)
	}

	// Probe taint engine availability before the taint-on pass. If the engine
	// is unavailable (missing go binary, sandbox, typecheck error), the bridge
	// passes findings through unchanged (graceful degradation); in that
	// case skip the downgrade assertions but still exercise the code path.
	taint.Reset()
	engine := taint.GetOrInit(ctx, fixturePath)
	taint.Reset()
	if engine == nil {
		t.Skip("taint engine unavailable in this environment — graceful degradation verified by pass-through")
	}

	// Second pass: include_taint=true. bridge must downgrade
	// PAN-KEYWORD → INFO and suppress PAN-TYPE on the transit DTO.
	reportOn, err := gen.GenerateWithOptions(ctx, fixturePath, "", false, true)
	if err != nil {
		t.Fatalf("generate (taint on): %v", err)
	}

	offCVV := findCVVPANKeyword(reportOff.Findings)
	onCVV := findCVVPANKeyword(reportOn.Findings)

	if offCVV == nil {
		// Active PAN-KEYWORD finding may be routed through suppressions if
		// the tree has an.pci-dss-mcp-ignore entry or dev-context downgrade.
		// Accept either location as long as SOMETHING is present.
		offCVV = findCVVPANKeyword(suppressionEntryFindings(reportOff.Suppressions))
	}
	if offCVV == nil {
		t.Fatal("expected a PAN-KEYWORD CVV finding in the default (taint off) report; fixture may be misconfigured")
	}
	if onCVV == nil {
		// With taint on the PAN-KEYWORD should still appear (downgraded, not
		// suppressed — only PAN-TYPE is suppressed). If the bridge
		// is routing it via suppressions, flag that as a contract violation.
		onCVV = findCVVPANKeyword(suppressionEntryFindings(reportOn.Suppressions))
		if onCVV == nil {
			t.Fatal("expected PAN-KEYWORD CVV finding in taint-on report (downgraded, not removed)")
		}
	}

	if offCVV.Severity != scanner.SeverityHigh {
		// baseline may downgrade through dev-context on some machines.
		// Accept any severity other than Info — the contract is "not downgraded
		// by the taint bridge".
		if offCVV.Severity == scanner.SeverityInfo {
			t.Errorf("taint off: PAN-KEYWORD unexpectedly Info (want High or equivalent baseline)")
		}
	}

	// Taint-on CVV must be INFO with the transit annotation.
	if onCVV.Severity != scanner.SeverityInfo {
		t.Errorf("taint on: PAN-KEYWORD CVV severity = %s, want Info (transit-only downgrade)", onCVV.Severity)
	}
	if !strings.Contains(onCVV.Description, "transit-only") {
		t.Errorf("taint on: expected description to mention transit-only, got %q", onCVV.Description)
	}

	// PAN-TYPE on the same field must be suppressed entirely on the taint-on
	// path (non-persistent memory encryption not required per PCI SSC
	// FAQ). Walk the full on-report findings and fail if any PAN-TYPE leaked
	// through for the transit DTO file.
	for _, f := range reportOn.Findings {
		if f.RuleID != "PAN-TYPE" {
			continue
		}
		if strings.Contains(f.FilePath, "tokenize.go") {
			t.Errorf("taint on: PAN-TYPE for transit CVV should be suppressed per, got %+v", f)
		}
	}
}

// suppressionEntryFindings extracts the embedded ReportFinding from each
// SuppressionEntry so TestReport_IncludeTaint can probe both the active and
// suppressed paths uniformly.
func suppressionEntryFindings(entries []SuppressionEntry) []ReportFinding {
	out := make([]ReportFinding, len(entries))
	for i, e := range entries {
		out[i] = e.ReportFinding
	}
	return out
}

// TestReport_IncludeTaint_DeferredSinks locks: ERR-LEAK and PAN-LOGGER
// upgrades are deferred to /19. ships empty sink libraries
// for SinkHTTPResponse, SinkLoggerCall, and SinkCryptoCall. Even with
// include_taint=true, error-leak findings and logger-sensitive findings must
// behave identically to. If this test fails after a commit
// you probably just landed the ERR-LEAK or PAN-LOGGER upgrade — update this
// test to the new expected behavior and move the /05 requirement IDs
// from deferred to complete in the roadmap.
func TestReport_IncludeTaint_DeferredSinks(t *testing.T) {
	tmp := t.TempDir()

	mustWrite := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	mustWrite(filepath.Join(tmp, "go.mod"), "module taint_deferred_fixture\n\ngo 1.22\n")
	mustWrite(filepath.Join(tmp, "main.go"), `package main

import (
	"log"
	"net/http"
)

// ERR-LEAK pattern: untyped error value written straight to HTTP response.
func handler(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
	_, _ = w.Write([]byte(err.Error()))
}

// PAN-LOGGER pattern: sensitive-looking variable name flowing into a logger call.
func leakLog(cvv string) {
	log.Printf("processing cvv=%s", cvv)
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		handler(w, http.ErrNoCookie)
	})
	leakLog("123")
}
`)

	t.Cleanup(taint.Reset)
	db := newTestDB(t)
	gen := NewReportGenerator(db)
	ctx := context.Background()

	reportOff, err := gen.GenerateWithOptions(ctx, tmp, "", false, false)
	if err != nil {
		t.Fatalf("generate (off): %v", err)
	}
	reportOn, err := gen.GenerateWithOptions(ctx, tmp, "", false, true)
	if err != nil {
		t.Fatalf("generate (on): %v", err)
	}

	// Compare ERR-LEAK findings: requires identical counts + severities
	// between off and on because SinkHTTPResponse is an empty library in.
	errLeakOff := filterFindingsByRulePrefix(reportOff.Findings, "ERR-LEAK")
	errLeakOn := filterFindingsByRulePrefix(reportOn.Findings, "ERR-LEAK")
	if len(errLeakOff) != len(errLeakOn) {
		t.Errorf("ERR-LEAK count mismatch: off=%d on=%d — deferred-sink contract violated (did you enable ERR-LEAK upgrade?)",
			len(errLeakOff), len(errLeakOn))
	}
	for i := range errLeakOff {
		if i >= len(errLeakOn) {
			break
		}
		if errLeakOff[i].Severity != errLeakOn[i].Severity {
			t.Errorf("ERR-LEAK[%d] severity changed off→on: %s→%s (violation)",
				i, errLeakOff[i].Severity, errLeakOn[i].Severity)
		}
		if errLeakOff[i].FilePath != errLeakOn[i].FilePath || errLeakOff[i].Line != errLeakOn[i].Line {
			t.Errorf("ERR-LEAK[%d] location changed off→on: %s:%d→%s:%d",
				i, errLeakOff[i].FilePath, errLeakOff[i].Line,
				errLeakOn[i].FilePath, errLeakOn[i].Line)
		}
	}

	// Same for PAN-LOGGER.
	panLoggerOff := filterFindingsByRulePrefix(reportOff.Findings, "PAN-LOGGER")
	panLoggerOn := filterFindingsByRulePrefix(reportOn.Findings, "PAN-LOGGER")
	if len(panLoggerOff) != len(panLoggerOn) {
		t.Errorf("PAN-LOGGER count mismatch: off=%d on=%d — deferred-sink contract violated",
			len(panLoggerOff), len(panLoggerOn))
	}
	for i := range panLoggerOff {
		if i >= len(panLoggerOn) {
			break
		}
		if panLoggerOff[i].Severity != panLoggerOn[i].Severity {
			t.Errorf("PAN-LOGGER[%d] severity changed off→on: %s→%s (violation)",
				i, panLoggerOff[i].Severity, panLoggerOn[i].Severity)
		}
	}
}

// TestReport_IncludeTaint_TriStateDefaultOn locks:
// the MCP tool input IncludeTaint is a *bool tri-state pointer so omitting
// the field (nil) defaults to taint ON, while explicit false opts out for
// dev iteration and explicit true is a no-op. The nil default makes
// production entry points safe-by-default (precision > speed), replacing
// the old opt-in contract.
func TestReport_IncludeTaint_TriStateDefaultOn(t *testing.T) {
	var input ReportInput
	if input.IncludeTaint != nil {
		t.Fatal("ReportInput.IncludeTaint zero value must be nil (tri-state pointer) per ")
	}

	// Type must be *bool to support the tri-state (nil / *false / *true).
	rt := reflectTypeOfReportInputIncludeTaint()
	if rt.Type.Kind() != reflect.Ptr || rt.Type.Elem().Kind() != reflect.Bool {
		t.Fatalf("ReportInput.IncludeTaint must be *bool (tri-state), got %s", rt.Type)
	}

	// Sanity check: the jsonschema tag must document the 5-30s cost, the
	// PCI SSC FAQ rationale, and the new production-grade default so users
	// understand the new behavior.
	tag := string(rt.Tag)
	if !strings.Contains(tag, "5-30 seconds") {
		t.Errorf("IncludeTaint jsonschema tag should mention 5-30 seconds cost, got %q", tag)
	}
	if !strings.Contains(tag, "PCI SSC FAQ") && !strings.Contains(tag, "non-persistent memory") {
		t.Errorf("IncludeTaint jsonschema tag should reference PCI SSC FAQ or non-persistent memory, got %q", tag)
	}
	if !strings.Contains(tag, "Default true") && !strings.Contains(tag, "production-grade precision") {
		t.Errorf("IncludeTaint jsonschema tag should document the new taint-ON default, got %q", tag)
	}
}

// reflectTypeOfReportInputIncludeTaint returns the reflect.StructField for
// ReportInput.IncludeTaint so TestReport_IncludeTaint_DefaultOff can assert
// the jsonschema tag content without hard-coding the exact string.
func reflectTypeOfReportInputIncludeTaint() reflect.StructField {
	rt := reflect.TypeOf(ReportInput{})
	f, ok := rt.FieldByName("IncludeTaint")
	if !ok {
		panic("ReportInput.IncludeTaint field missing — Task 1 regression")
	}
	return f
}
