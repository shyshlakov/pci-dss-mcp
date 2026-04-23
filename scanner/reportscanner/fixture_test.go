package reportscanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestVulnerablePaymentServiceFixture(t *testing.T) {
	ctx := context.Background()
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	// copyFixtureTree strips the "testdata" path segment so scanner.DefaultExcludeDirs
	// (scanner/walker.go:29) does not skip the entire tree. Without this, every
	// expected finding row would fail as MISSING.
	scanRoot := copyFixtureTree(t, fixtureRoot)
	contractPath := filepath.Join(fixtureRoot, "EXPECTED-FINDINGS.md")

	contract, err := parseExpectedContract(contractPath)
	if err != nil {
		t.Fatalf("parse expected contract: %v", err)
	}
	if len(contract.violations) == 0 {
		t.Fatal("contract parsed zero violations -- likely parser bug or empty table")
	}

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	gen := NewReportGenerator(db)

	report, err := gen.GenerateWithOptions(ctx, scanRoot, "", false, true)
	if err != nil {
		t.Fatalf("GenerateWithOptions: %v", err)
	}
	if report == nil {
		t.Fatal("GenerateWithOptions returned nil report")
	}

	actual := report.Findings

	t.Run("expected_violations_present", func(tt *testing.T) {
		for _, want := range contract.violations {
			if !findingPresent(actual, want) {
				tt.Errorf("MISSING expected finding: rule=%s severity=%s file=%s line=%d", want.RuleID, want.Severity, want.FilePath, want.Line)
			}
		}
	})

	t.Run("no_unexpected_active_findings", func(tt *testing.T) {
		for _, got := range actual {
			if isInfoSeverity(got.Severity) {
				continue
			}
			if !expectedMatches(contract.violations, got) {
				tt.Errorf("UNEXPECTED finding (drift): rule=%s severity=%s file=%s line=%d", got.RuleID, got.Severity, got.FilePath, got.Line)
			}
		}
	})

	t.Run("clean_files_have_no_active_findings", func(tt *testing.T) {
		for _, cleanFile := range contract.cleanFiles {
			cleanFile = strings.TrimSpace(strings.SplitN(cleanFile, " ", 2)[0])
			if cleanFile == "" {
				continue
			}
			for _, got := range actual {
				if isInfoSeverity(got.Severity) {
					continue
				}
				if strings.HasSuffix(filepath.ToSlash(got.FilePath), cleanFile) {
					tt.Errorf("CLEAN file produced active finding: file=%s rule=%s severity=%s", cleanFile, got.RuleID, got.Severity)
				}
			}
		}
	})

	t.Run("severity_summary_matches", func(tt *testing.T) {
		got := summariseBySeverity(actual)
		want := contract.frontmatter.ExpectedSummary
		for sev, wantCount := range want {
			if strings.EqualFold(sev, "info") {
				continue
			}
			gotCount := got[strings.ToLower(sev)]
			if absInt(gotCount-wantCount) > 0 {
				tt.Errorf("severity %s: want %d got %d", sev, wantCount, gotCount)
			}
		}
	})

	t.Run("requirement_id_matches", func(tt *testing.T) {
		for _, want := range contract.violations {
			if want.RequirementID == "" && len(want.RelatedRequirements) == 0 {
				continue
			}
			got, ok := findActualFinding(actual, want)
			if !ok {
				continue
			}
			if want.RequirementID != "" && got.RequirementID != want.RequirementID {
				tt.Errorf("req_id mismatch: rule=%s file=%s line=%d: want %q got %q",
					want.RuleID, want.FilePath, want.Line, want.RequirementID, got.RequirementID)
			}
			if len(want.RelatedRequirements) > 0 && !equalStringSetsIgnoreOrder(got.RelatedRequirements, want.RelatedRequirements) {
				tt.Errorf("related mismatch: rule=%s file=%s line=%d: want %v got %v",
					want.RuleID, want.FilePath, want.Line, want.RelatedRequirements, got.RelatedRequirements)
			}
		}
	})
}

// TestVulnerablePaymentServiceFixture_LivePath is the defense-in-depth
// regression guard for the scanner path-dependency class of bugs.
// It scans the fixture at its real in-repo path (no tmpdir copy) to catch
// the class of path-dependency bug where devcontext segment matching or the
// taint bridge silently diverge between an in-repo relative scan root and
// an out-of-tree absolute one. The primary tmpdir-based test remains the
// authoritative contract validator; this variant asserts only that all
// contractually-expected findings are present and the severity summary
// matches. A failure here with the primary test still passing points at
// another path-dependent scanner that needs projectRoot plumbed through.
func TestVulnerablePaymentServiceFixture_LivePath(t *testing.T) {
	ctx := context.Background()
	scanRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	contractPath := filepath.Join(scanRoot, "EXPECTED-FINDINGS.md")

	contract, err := parseExpectedContract(contractPath)
	if err != nil {
		t.Fatalf("parse expected contract: %v", err)
	}
	if len(contract.violations) == 0 {
		t.Fatal("contract parsed zero violations -- likely parser bug or empty table")
	}

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	gen := NewReportGenerator(db)

	report, err := gen.GenerateWithOptions(ctx, scanRoot, "", false, true)
	if err != nil {
		t.Fatalf("GenerateWithOptions: %v", err)
	}
	if report == nil {
		t.Fatal("GenerateWithOptions returned nil report")
	}

	actual := report.Findings

	t.Run("expected_violations_present", func(tt *testing.T) {
		for _, want := range contract.violations {
			if !findingPresent(actual, want) {
				tt.Errorf("MISSING expected finding on live path: rule=%s severity=%s file=%s line=%d", want.RuleID, want.Severity, want.FilePath, want.Line)
			}
		}
	})

	t.Run("severity_summary_matches", func(tt *testing.T) {
		got := summariseBySeverity(actual)
		want := contract.frontmatter.ExpectedSummary
		for sev, wantCount := range want {
			if strings.EqualFold(sev, "info") {
				continue
			}
			gotCount := got[strings.ToLower(sev)]
			if absInt(gotCount-wantCount) > 0 {
				tt.Errorf("live path severity %s: want %d got %d -- likely a path-dependent scanner regression", sev, wantCount, gotCount)
			}
		}
	})
}

func findingPresent(haystack []ReportFinding, want expectedFinding) bool {
	for _, f := range haystack {
		if f.RuleID != want.RuleID {
			continue
		}
		if !strings.EqualFold(string(f.Severity), want.Severity) {
			continue
		}
		if !strings.HasSuffix(filepath.ToSlash(f.FilePath), want.FilePath) {
			continue
		}
		if want.Line > 0 && absInt(f.Line-want.Line) > 2 {
			continue
		}
		return true
	}
	return false
}

func expectedMatches(expected []expectedFinding, got ReportFinding) bool {
	for _, e := range expected {
		if e.RuleID != got.RuleID {
			continue
		}
		if !strings.EqualFold(e.Severity, string(got.Severity)) {
			continue
		}
		if !strings.HasSuffix(filepath.ToSlash(got.FilePath), e.FilePath) {
			continue
		}
		return true
	}
	return false
}

func isInfoSeverity(s scanner.Severity) bool {
	return s == scanner.SeverityInfo ||
		strings.EqualFold(string(s), "info") ||
		strings.EqualFold(string(s), "informational")
}

func summariseBySeverity(findings []ReportFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[strings.ToLower(string(f.Severity))]++
	}
	return out
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func TestReportLayerA_IncludesHistogram(t *testing.T) {
	ctx := context.Background()
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTree(t, fixtureRoot)

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	gen := NewReportGenerator(db)

	includeTaint := true
	input := ReportInput{
		Path:         scanRoot,
		MinSeverity:  "MEDIUM",
		IncludeTaint: &includeTaint,
	}
	_, flat, _, err := SelectAndExecute(ctx, gen, input, "generate_compliance_report")
	if err != nil {
		t.Fatalf("SelectAndExecute: %v", err)
	}
	if flat == nil {
		t.Fatalf("expected FlatResponse, got nil")
	}
	if flat.ResponseShape != "flat" {
		t.Errorf("response_shape=%q want flat", flat.ResponseShape)
	}
	if len(flat.Summary.ByRule) == 0 {
		t.Errorf("Summary.ByRule empty; expected full-scan histogram entries")
	}
	if len(flat.Summary.ByRule) > 10 {
		t.Errorf("Summary.ByRule len=%d must be <=10", len(flat.Summary.ByRule))
	}
	if flat.Summary.Critical+flat.Summary.High+flat.Summary.Medium < 1 {
		t.Errorf("embedded ReportSummary severity counts empty: %+v", flat.Summary.ReportSummary)
	}
}

func TestReportToolDescription_LayerAHistogramNeedle(t *testing.T) {
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "report-desc", Version: "v0.0.1"}, nil)
	RegisterTools(server, db)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "report-desc-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	defer func() { _ = session.Close() }()
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var desc string
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "generate_compliance_report" {
			continue
		}
		found = true
		desc = tool.Description
	}
	if !found {
		t.Fatalf("generate_compliance_report not in ListTools")
	}
	needles := []string{"summary.by_severity", "summary.by_rule", "full-scan"}
	for _, n := range needles {
		if !strings.Contains(desc, n) {
			t.Errorf("generate_compliance_report description missing substring %q", n)
		}
	}
}
