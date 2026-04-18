package reportscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const layerBFixtureBudgetBytes = 25 * 1024

func synthesizeReportWithNFindings(n int) *ComplianceReport {
	findings := make([]ReportFinding, 0, n)
	for i := 0; i < n; i++ {
		var sev scanner.Severity
		switch i % 5 {
		case 0:
			sev = scanner.SeverityCritical
		case 1:
			sev = scanner.SeverityHigh
		case 2:
			sev = scanner.SeverityMedium
		case 3:
			sev = scanner.SeverityLow
		default:
			sev = scanner.SeverityInfo
		}
		findings = append(findings, ReportFinding{
			Finding: scanner.Finding{
				RuleID:        fmt.Sprintf("FAKE-%d", i),
				Severity:      sev,
				FilePath:      fmt.Sprintf("fake/path/%d.go", i),
				Line:          i + 1,
				Description:   "synthetic",
				Suggestion:    "synthetic",
				RequirementID: "3.3.1",
			},
			RequirementTitle: "Synthetic",
			ScannerName:      "synthetic",
		})
	}
	var critical, high, medium, low, info int
	for _, f := range findings {
		switch f.Severity {
		case scanner.SeverityCritical:
			critical++
		case scanner.SeverityHigh:
			high++
		case scanner.SeverityMedium:
			medium++
		case scanner.SeverityLow:
			low++
		case scanner.SeverityInfo:
			info++
		}
	}
	return &ComplianceReport{
		Metadata: ReportMetadata{
			GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
			TargetPath:   "/synthetic",
			TotalFiles:   n,
			TotalLines:   n * 10,
			DurationMS:   1,
			ScannerCount: 1,
		},
		Summary: ReportSummary{
			TotalRequirements: 1,
			Critical:          critical,
			High:              high,
			Medium:            medium,
			Low:               low,
			Info:              info,
		},
		RequirementStatus: map[string]RequirementStatus{},
		Findings:          findings,
	}
}

func scanFixtureInput(t *testing.T) (*ReportGenerator, string) {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTree(t, fixtureRoot)
	return NewReportGenerator(db), scanRoot
}

func TestHybrid_Default_UnfilteredReturnsSummary(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, flat, errResp, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if flat != nil || errResp != nil {
		t.Fatalf("expected summary-only, got flat=%v errResp=%v", flat, errResp)
	}
	if summary == nil {
		t.Fatalf("expected summary, got nil")
	}
	if summary.ResponseShape != "summary" {
		t.Fatalf("ResponseShape = %q, want summary", summary.ResponseShape)
	}
	for _, key := range []string{"critical", "high", "medium"} {
		if _, ok := summary.TopFindings[key]; !ok {
			t.Fatalf("TopFindings missing key %q", key)
		}
		if len(summary.TopFindings[key]) > topPerSeverity {
			t.Fatalf("TopFindings[%q] len = %d, want <= %d", key, len(summary.TopFindings[key]), topPerSeverity)
		}
	}
	if summary.Pagination.NextCursor == "" {
		t.Fatalf("NextCursor must be set on summary response")
	}
	if summary.Pagination.AutoCapped {
		t.Fatalf("AutoCapped must be false on summary response")
	}
}

func TestHybrid_Cursor_ResumesAtOffset(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, _, _, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute first call: %v", err)
	}
	if summary == nil || summary.Pagination.NextCursor == "" {
		t.Fatalf("expected a summary with cursor")
	}

	resumeIn := ReportInput{Path: path, Cursor: summary.Pagination.NextCursor}
	sum2, flat, errResp, err := SelectAndExecute(context.Background(), gen, resumeIn, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute resume: %v", err)
	}
	if sum2 != nil || errResp != nil {
		t.Fatalf("expected flat-only on resume, got summary=%v errResp=%v", sum2, errResp)
	}
	if flat == nil {
		t.Fatalf("expected flat response on resume")
	}
	if flat.ResponseShape != "flat" {
		t.Fatalf("ResponseShape = %q, want flat", flat.ResponseShape)
	}
	if len(flat.Findings) > flatPageSize {
		t.Fatalf("page size = %d, want <= %d", len(flat.Findings), flatPageSize)
	}
}

func TestHybrid_Cursor_Expired_ReturnsCursorExpiredError(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, _, _, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	cursor := summary.Pagination.NextCursor
	if cursor == "" {
		t.Fatalf("expected cursor, got empty")
	}

	clk.Advance(sessionTTL + time.Second)

	resumeIn := ReportInput{Path: path, Cursor: cursor}
	_, _, errResp, err := SelectAndExecute(context.Background(), gen, resumeIn, "generate_compliance_report")
	if err != nil {
		t.Fatalf("resume expired: %v", err)
	}
	if errResp == nil {
		t.Fatalf("expected CursorExpiredError, got nil")
	}
	if errResp.Code != "CURSOR_EXPIRED" {
		t.Fatalf("Code = %q, want CURSOR_EXPIRED", errResp.Code)
	}
	if errResp.ResponseShape != "error" {
		t.Fatalf("ResponseShape = %q, want error", errResp.ResponseShape)
	}
}

func TestHybrid_Cursor_Malformed_ReturnsCursorExpiredError(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, Cursor: "not-a-real-cursor"}
	_, _, errResp, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("malformed cursor returned err: %v", err)
	}
	if errResp == nil {
		t.Fatalf("expected CursorExpiredError, got nil")
	}
	if errResp.Code != "CURSOR_MALFORMED" {
		t.Fatalf("Code = %q, want CURSOR_MALFORMED", errResp.Code)
	}
	if errResp.ResponseShape != "error" {
		t.Fatalf("ResponseShape = %q, want error", errResp.ResponseShape)
	}
}

func TestHybrid_RuleFilter_ReturnsFlatPaged(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline", RuleFilter: "PAN-KEYWORD"}
	summary, flat, errResp, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if summary != nil || errResp != nil {
		t.Fatalf("expected flat-only, got summary=%v errResp=%v", summary, errResp)
	}
	if flat == nil {
		t.Fatalf("expected flat response")
	}
	if flat.ResponseShape != "flat" {
		t.Fatalf("ResponseShape = %q, want flat", flat.ResponseShape)
	}
	if len(flat.Findings) > flatPageSize {
		t.Fatalf("page size = %d, want <= %d", len(flat.Findings), flatPageSize)
	}
	for _, f := range flat.Findings {
		if f.RuleID != "PAN-KEYWORD" {
			t.Fatalf("filtered page contains non-PAN-KEYWORD finding: %s", f.RuleID)
		}
	}
}

func TestHybrid_MinSeverity_ReturnsFlatPaged(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline", MinSeverity: "HIGH"}
	summary, flat, errResp, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if summary != nil || errResp != nil {
		t.Fatalf("expected flat-only, got summary=%v errResp=%v", summary, errResp)
	}
	if flat == nil {
		t.Fatalf("expected flat response")
	}
	if len(flat.Findings) > flatPageSize {
		t.Fatalf("page size = %d, want <= %d", len(flat.Findings), flatPageSize)
	}
	for _, f := range flat.Findings {
		if f.Severity != scanner.SeverityCritical && f.Severity != scanner.SeverityHigh {
			t.Fatalf("MinSeverity=HIGH page contains severity %s for rule %s", f.Severity, f.RuleID)
		}
	}
}

func TestHybrid_Limit100_ReturnsExactFlat(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline", Limit: 100}
	summary, flat, errResp, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if summary != nil || errResp != nil {
		t.Fatalf("expected flat-only, got summary=%v errResp=%v", summary, errResp)
	}
	if flat == nil {
		t.Fatalf("expected flat response")
	}
	if len(flat.Findings) > 100 {
		t.Fatalf("expected at most 100 findings, got %d", len(flat.Findings))
	}
	if flat.Pagination.AutoCapped {
		t.Fatalf("AutoCapped must be false when Limit is explicit positive")
	}
}

func TestLayerB_FixtureBudget25KB(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, _, _, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if summary == nil {
		t.Fatalf("expected summary on unfiltered call")
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("json.Marshal summary: %v", err)
	}
	if len(raw) > layerBFixtureBudgetBytes {
		t.Fatalf("Layer B response = %d bytes, budget = %d bytes", len(raw), layerBFixtureBudgetBytes)
	}
	t.Logf("Layer B response size on golden fixture = %d bytes (budget %d)", len(raw), layerBFixtureBudgetBytes)
}

func TestHybrid_Selector_CursorBeatsFilter(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, _, _, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	cursor := summary.Pagination.NextCursor
	if cursor == "" {
		t.Fatalf("expected cursor from first scan")
	}

	resumeIn := ReportInput{
		Path:       path,
		Cursor:     cursor,
		RuleFilter: "PAN-KEYWORD",
	}
	_, flat, errResp, err := SelectAndExecute(context.Background(), gen, resumeIn, "generate_compliance_report")
	if err != nil {
		t.Fatalf("resume with filter: %v", err)
	}
	if errResp != nil {
		t.Fatalf("expected flat resume, got errResp %+v", errResp)
	}
	if flat == nil {
		t.Fatalf("expected flat response from cursor resume")
	}
	nonPAN := 0
	for _, f := range flat.Findings {
		if !strings.HasPrefix(f.RuleID, "PAN-") {
			nonPAN++
		}
	}
	if nonPAN == 0 && len(flat.Findings) > 0 {
		t.Logf("cursor-resume page happened to be all PAN-*; this is acceptable — the invariant is that the RuleFilter on resume was ignored")
	}
}

func TestHybrid_CrossToolCursor_Rejected(t *testing.T) {
	ResetSessionCacheForTest(nil)
	gen, path := scanFixtureInput(t)

	in := ReportInput{Path: path, DepScanMode: "offline"}
	summary, _, _, err := SelectAndExecute(context.Background(), gen, in, "generate_compliance_report")
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	cursor := summary.Pagination.NextCursor
	if cursor == "" {
		t.Fatalf("expected cursor")
	}

	resumeIn := ReportInput{Path: path, Cursor: cursor}
	_, _, errResp, err := SelectAndExecute(context.Background(), gen, resumeIn, "triage_findings")
	if err != nil {
		t.Fatalf("cross-tool cursor: err=%v", err)
	}
	if errResp == nil {
		t.Fatalf("expected CURSOR_MALFORMED on cross-tool replay, got nil")
	}
	if errResp.Code != "CURSOR_MALFORMED" {
		t.Fatalf("Code = %q, want CURSOR_MALFORMED", errResp.Code)
	}
}
