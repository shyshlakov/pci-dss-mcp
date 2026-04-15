package panscanner_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
)

// taintFixturePath returns the absolute path to a panscanner taint fixture
// directory under testdata/taint/. The defaultExcludePatterns include
// "testdata/" so callers MUST pass an empty exclude slice to ScanFullWithTaint
// AND set includeUntracked=true (these fixtures are not git-tracked because
// they import only stdlib and have their own go.mod).
func taintFixturePath(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", "taint", name))
	if err != nil {
		t.Fatalf("abs path for %s: %v", name, err)
	}
	return abs
}

// scanTaintFixture runs panscanner against a taint fixture with includeTaint
// matching the test's intent. Always uses includeUntracked=true and an empty
// exclude slice so the fixture files (which live under testdata/) are visible.
func scanTaintFixture(t *testing.T, fixture string, includeTaint bool) []scanner.Finding {
	t.Helper()
	t.Cleanup(taint.Reset)
	s := panscanner.New()
	result, err := s.ScanFullWithTaint(
		context.Background(),
		taintFixturePath(t, fixture),
		[]string{}, // override default excludes — testdata/ would otherwise filter the fixture
		false,      // includeTests
		true,       // includeUntracked: fixture files are not git-tracked
		includeTaint,
	)
	if err != nil {
		t.Fatalf("ScanFullWithTaint(%s) error: %v", fixture, err)
	}
	return result.Findings
}

// findByRule scans the slice for the first finding with the given rule and
// description substring (case-insensitive). Returns nil when nothing matches.
func findByRule(findings []scanner.Finding, rule, descSubstr string) *scanner.Finding {
	for i, f := range findings {
		if f.RuleID != rule {
			continue
		}
		if descSubstr == "" || strings.Contains(strings.ToLower(f.Description), strings.ToLower(descSubstr)) {
			return &findings[i]
		}
	}
	return nil
}

// requireTaintEngine skips the test when the taint engine cannot be initialized
// (no go binary on PATH, broken sandbox, etc). The bridge's graceful
// degradation is exercised separately by TestPANKeyword_TaintUnavailable.
func requireTaintEngine(t *testing.T, fixture string) {
	t.Helper()
	t.Cleanup(taint.Reset)
	engine := taint.GetOrInit(context.Background(), taintFixturePath(t, fixture))
	if engine == nil {
		t.Skip("taint engine unavailable in this environment (no go binary, sandbox, or typecheck error)")
	}
	// Reset so the test under control re-initializes the cache itself.
	taint.Reset()
}

// TestPANKeyword_TaintTransit (row 1): a transit DTO whose CHD field
// flows only to an HTTP client must have its PAN-KEYWORD finding downgraded
// to INFO with the PCI SSC FAQ annotation.
func TestPANKeyword_TaintTransit(t *testing.T) {
	requireTaintEngine(t, "transit")
	findings := scanTaintFixture(t, "transit", true)

	cvv := findByRule(findings, "PAN-KEYWORD", "cvv")
	if cvv == nil {
		t.Fatalf("expected PAN-KEYWORD finding for CVV, got: %+v", findings)
	}
	if cvv.Severity != scanner.SeverityInfo {
		t.Errorf("transit CVV PAN-KEYWORD severity = %s, want INFO", cvv.Severity)
	}
	if !strings.Contains(strings.ToLower(cvv.Description), "transit-only") {
		t.Errorf("expected description to mention transit-only, got %q", cvv.Description)
	}
	if !strings.Contains(strings.ToLower(cvv.Description), "non-persistent memory") {
		t.Errorf("expected description to mention non-persistent memory (PCI SSC FAQ), got %q", cvv.Description)
	}
}

// TestPANKeyword_TaintStored (row 1): a persistent model whose CHD
// fields reach a database/sql sink must keep PAN-KEYWORD at HIGH and pick up
// the "flows to DB storage sink" annotation plus confidence=high.
func TestPANKeyword_TaintStored(t *testing.T) {
	requireTaintEngine(t, "stored")
	findings := scanTaintFixture(t, "stored", true)

	cardNumber := findByRule(findings, "PAN-KEYWORD", "cardnumber")
	if cardNumber == nil {
		t.Fatalf("expected PAN-KEYWORD finding for CardNumber, got: %+v", findings)
	}
	if cardNumber.Severity != scanner.SeverityHigh && cardNumber.Severity != scanner.SeverityCritical {
		t.Errorf("stored CardNumber PAN-KEYWORD severity = %s, want HIGH or CRITICAL", cardNumber.Severity)
	}
	if !strings.Contains(strings.ToLower(cardNumber.Description), "flows to db") {
		t.Errorf("expected description to mention DB flow, got %q", cardNumber.Description)
	}
	if cardNumber.Confidence != "high" {
		t.Errorf("stored CardNumber confidence = %q, want high", cardNumber.Confidence)
	}
}

// TestPANKeyword_TaintInconclusive (row 3 + update):
// a PAN-like CHD field in a non-transit-shape path with no resolvable DB
// sink must KEEP its existing HIGH severity. adds a negative
// evidence heuristic for SAD field names (CVV/CVC/SecurityCode), but PAN
// field names are DELIBERATELY excluded, so this test now exercises the
// true-inconclusive branch via PrimaryAccountNumber. The bridge's
// belt-and-braces isTransitShape check guards against false negatives even
// when FlowsTo says no DB flow exists.
func TestPANKeyword_TaintInconclusive(t *testing.T) {
	requireTaintEngine(t, "inconclusive")
	findings := scanTaintFixture(t, "inconclusive", true)

	pan := findByRule(findings, "PAN-KEYWORD", "primaryaccountnumber")
	if pan == nil {
		t.Fatalf("expected PAN-KEYWORD finding for PrimaryAccountNumber, got: %+v", findings)
	}
	if pan.Severity == scanner.SeverityInfo {
		t.Errorf("inconclusive PrimaryAccountNumber PAN-KEYWORD severity unexpectedly downgraded to INFO; want HIGH or CRITICAL (PAN excluded from negative evidence)")
	}
	if strings.Contains(strings.ToLower(pan.Description), "transit-only") {
		t.Errorf("inconclusive finding description must NOT claim transit-only, got %q", pan.Description)
	}
}

// TestPANType_TaintTransit_Suppressed ( + row 1 PAN-TYPE column):
// a string-typed CHD field in a transit DTO must be SUPPRESSED entirely. The
// PAN-KEYWORD on the same field is downgraded to INFO; PAN-TYPE disappears.
func TestPANType_TaintTransit_Suppressed(t *testing.T) {
	requireTaintEngine(t, "transit")
	findings := scanTaintFixture(t, "transit", true)

	for _, f := range findings {
		if f.RuleID == "PAN-TYPE" {
			t.Errorf("PAN-TYPE finding %q must be suppressed for transit-only CHD per, got: %+v", f.Description, f)
		}
	}
	// Sanity: the PAN-KEYWORD survivor must still exist and be downgraded.
	if cvv := findByRule(findings, "PAN-KEYWORD", "cvv"); cvv == nil {
		t.Fatal("expected at least one PAN-KEYWORD CVV finding to survive suppression")
	} else if cvv.Severity != scanner.SeverityInfo {
		t.Errorf("transit CVV PAN-KEYWORD severity = %s, want INFO", cvv.Severity)
	}
}

// TestPANKeyword_TaintUnavailable (graceful degradation): when the taint
// engine cannot initialize (no go binary), the bridge MUST pass findings
// through unchanged — same severities, no taint annotations.
func TestPANKeyword_TaintUnavailable(t *testing.T) {
	t.Cleanup(taint.Reset)
	t.Setenv("PATH", "")

	s := panscanner.New()
	result, err := s.ScanFullWithTaint(
		context.Background(),
		taintFixturePath(t, "transit"),
		[]string{},
		false,
		true,
		true, // includeTaint=true, but engine will be nil → pass-through
	)
	if err != nil {
		t.Fatalf("ScanFullWithTaint error: %v", err)
	}

	cvv := findByRule(result.Findings, "PAN-KEYWORD", "cvv")
	if cvv == nil {
		t.Fatalf("expected PAN-KEYWORD finding for CVV, got: %+v", result.Findings)
	}
	if cvv.Severity == scanner.SeverityInfo {
		t.Errorf("engine-unavailable CVV unexpectedly downgraded to INFO; bridge must pass-through")
	}
	if strings.Contains(strings.ToLower(cvv.Description), "transit-only") {
		t.Errorf("engine-unavailable finding must NOT carry taint annotation, got %q", cvv.Description)
	}
	// PAN-TYPE on the same transit field must also survive (no suppression
	// without engine confirmation).
	if pt := findByRule(result.Findings, "PAN-TYPE", "cvv"); pt == nil {
		t.Error("PAN-TYPE for CVV must survive when taint engine is unavailable")
	}
}

// TestPANKeyword_TaintDisabled ( + zero-regression): when the caller passes
// includeTaint=false on a fixture that WOULD be downgraded, the output must be
// identical to the existing ScanFull (no taint annotations, original severities).
func TestPANKeyword_TaintDisabled(t *testing.T) {
	t.Cleanup(taint.Reset)
	s := panscanner.New()

	resultOff, err := s.ScanFullWithTaint(
		context.Background(),
		taintFixturePath(t, "transit"),
		[]string{},
		false,
		true,
		false, // includeTaint=false
	)
	if err != nil {
		t.Fatalf("ScanFullWithTaint(includeTaint=false) error: %v", err)
	}

	cvv := findByRule(resultOff.Findings, "PAN-KEYWORD", "cvv")
	if cvv == nil {
		t.Fatalf("expected PAN-KEYWORD finding for CVV, got: %+v", resultOff.Findings)
	}
	if cvv.Severity == scanner.SeverityInfo {
		t.Errorf("includeTaint=false CVV unexpectedly downgraded to INFO; expected HIGH/CRITICAL pass-through")
	}
	if strings.Contains(strings.ToLower(cvv.Description), "(taint:") {
		t.Errorf("includeTaint=false finding must NOT carry taint annotation, got %q", cvv.Description)
	}
	if pt := findByRule(resultOff.Findings, "PAN-TYPE", "cvv"); pt == nil {
		t.Error("PAN-TYPE for CVV must survive when includeTaint=false")
	}

	// Cross-check: ScanFull (the legacy entry point) returns the same shape.
	resultLegacy, err := s.ScanFull(
		context.Background(),
		taintFixturePath(t, "transit"),
		[]string{},
		false,
		true,
	)
	if err != nil {
		t.Fatalf("ScanFull error: %v", err)
	}
	if len(resultOff.Findings) != len(resultLegacy.Findings) {
		t.Errorf("ScanFullWithTaint(false) and ScanFull returned different counts: %d vs %d",
			len(resultOff.Findings), len(resultLegacy.Findings))
	}
}

// TestStructTag_TransitDowngrade_NonTransitPath: verifies that
// a struct with json tags but no gorm/db tags at a file path that does NOT match
// isTransitShape (/requests/, /dto/, etc.) still gets downgraded to INFO when
// FlowsTo returns false. This is the core value of the struct tag heuristic:
// it replaces path-based detection as the primary guard.
func TestStructTag_TransitDowngrade_NonTransitPath(t *testing.T) {
	requireTaintEngine(t, "transit")
	findings := scanTaintFixture(t, "transit", true)

	// api_model_json_tags.go lives at the module root (NOT /requests/ or /dto/),
	// so isTransitShape would NOT match it. But the struct has json tags and no
	// gorm tags, so struct tag heuristic classifies it as transit.
	pan := findByRule(findings, "PAN-KEYWORD", "primaryaccountnumber")
	if pan == nil {
		t.Fatalf("expected PAN-KEYWORD finding for PrimaryAccountNumber from api_model_json_tags.go, got: %+v", findings)
	}
	if pan.Severity != scanner.SeverityInfo {
		t.Errorf("json-tagged transit struct PAN-KEYWORD severity = %s, want INFO (struct tag heuristic should downgrade regardless of file path)", pan.Severity)
	}
	if pan.Confidence != "high" {
		t.Errorf("json-tagged transit struct PAN-KEYWORD confidence = %q, want high", pan.Confidence)
	}
}

// TestStructTag_TransitSuppressPANTYPE_NonTransitPath: PAN-TYPE
// findings on json-tagged structs without gorm tags must be suppressed entirely,
// even when the file path does NOT match isTransitShape.
func TestStructTag_TransitSuppressPANTYPE_NonTransitPath(t *testing.T) {
	requireTaintEngine(t, "transit")
	findings := scanTaintFixture(t, "transit", true)

	// api_model_json_tags.go: PrimaryAccountNumber is declared as string -> PAN-TYPE
	// would be generated. The struct has json tags only -> struct tag heuristic says
	// transit -> PAN-TYPE must be suppressed.
	for _, f := range findings {
		if f.RuleID == "PAN-TYPE" && strings.Contains(strings.ToLower(f.Description), "primaryaccountnumber") {
			t.Errorf("PAN-TYPE for PrimaryAccountNumber on json-tagged transit struct must be suppressed, got: %+v", f)
		}
	}
}

// TestStructTag_StorageKeepsSeverity: a struct with gorm tags
// must keep its severity even when FlowsTo returns false. Storage structs should
// not be downgraded by the taint bridge.
func TestStructTag_StorageKeepsSeverity(t *testing.T) {
	requireTaintEngine(t, "stored")
	findings := scanTaintFixture(t, "stored", true)

	// db_model_gorm_tags.go has gorm:"column:number" -> storage classification.
	// Even if FlowsTo returns false for some reason, the struct tag says storage
	// so severity must NOT be downgraded.
	for _, f := range findings {
		if f.RuleID == "PAN-KEYWORD" && strings.Contains(strings.ToLower(f.Description), "number") {
			if f.Severity == scanner.SeverityInfo {
				t.Errorf("gorm-tagged storage struct PAN-KEYWORD should NOT be downgraded to INFO, got: %+v", f)
			}
		}
	}
}

// TestStructTag_InconclusiveFallsBackToPath ( + ):
// a struct with no tags and a NON-SAD field name (PrimaryAccountNumber / PAN-like)
// returns tagClassInconclusive from the heuristic and is NOT covered by the
// negative evidence heuristic (which fires only for
// CVV/CVC/SecurityCode). The bridge must fall back to isTransitShape path-based
// detection, which returns false for `/internal/storage/` paths, so severity
// is preserved.
func TestStructTag_InconclusiveFallsBackToPath(t *testing.T) {
	requireTaintEngine(t, "inconclusive")
	findings := scanTaintFixture(t, "inconclusive", true)

	// internal/storage/card.go: Card.PrimaryAccountNumber is a PAN field with
	// no struct tags. deliberately EXCLUDES PAN field names from
	// negative evidence (PAN can be legitimately stored per PCI DSS 3.5.1),
	// so the decision chain reaches isTransitShape fallback → /internal/storage/
	// is not a transit shape → severity kept.
	pan := findByRule(findings, "PAN-KEYWORD", "primaryaccountnumber")
	if pan == nil {
		t.Fatalf("expected PAN-KEYWORD finding for PrimaryAccountNumber, got: %+v", findings)
	}
	if pan.Severity == scanner.SeverityInfo {
		t.Errorf("tagless struct PrimaryAccountNumber (PAN) PAN-KEYWORD should NOT be downgraded to INFO (inconclusive -> negative evidence skipped for PAN -> path fallback -> not transit shape), severity = %s", pan.Severity)
	}
	// The same finding's file path must be /internal/storage/ (not matching
	// any isTransitShape marker) so that we truly exercise the path fallback.
	if !strings.Contains(strings.ToLower(pan.FilePath), "/internal/storage/") {
		t.Errorf("expected PrimaryAccountNumber finding at /internal/storage/ path, got %q", pan.FilePath)
	}
}

// TestNegativeEvidence_TaglessCVVDowngraded (Option B):
// a CVV field in a tagless domain model whose file path does NOT match any
// isTransitShape marker must still be downgraded to INFO via the negative
// internal/service/tokens/model/model.go:CVV pattern.
func TestNegativeEvidence_TaglessCVVDowngraded(t *testing.T) {
	requireTaintEngine(t, "inconclusive")
	findings := scanTaintFixture(t, "inconclusive", true)

	// domain_model_no_tags.go: ProvisionTokenCard.CVV in package storage at
	// module root. No tags (HasJSONTag=false, HasDBTag=false), no DB sink
	// reachable, so FlowsTo=false and structTagClassification=inconclusive.
	// Negative evidence heuristic recognizes "CVV" as a SAD field name and
	// downgrades to INFO regardless of file path.
	cvv := findByRule(findings, "PAN-KEYWORD", "cvv")
	if cvv == nil {
		t.Fatalf("expected PAN-KEYWORD finding for CVV, got: %+v", findings)
	}
	if cvv.Severity != scanner.SeverityInfo {
		t.Errorf("tagless struct CVV PAN-KEYWORD should be downgraded to INFO via negative evidence heuristic, got severity = %s", cvv.Severity)
	}
	if cvv.Confidence != "high" {
		t.Errorf("tagless struct CVV PAN-KEYWORD confidence = %q, want high (negative evidence is high-confidence)", cvv.Confidence)
	}
	if !strings.Contains(strings.ToLower(cvv.Description), "transit-only") {
		t.Errorf("expected description to mention transit-only after negative evidence downgrade, got %q", cvv.Description)
	}
}

// TestNegativeEvidence_TaglessCVV_PANTYPESuppressed:
// PAN-TYPE findings on tagless domain models with SAD field names must be
// suppressed entirely — same rule as PAN-TYPE suppression under
// tagClassTransit, but reached via the negative evidence path.
func TestNegativeEvidence_TaglessCVV_PANTYPESuppressed(t *testing.T) {
	requireTaintEngine(t, "inconclusive")
	findings := scanTaintFixture(t, "inconclusive", true)

	for _, f := range findings {
		if f.RuleID != "PAN-TYPE" {
			continue
		}
		if strings.Contains(strings.ToLower(f.Description), "cvv") {
			t.Errorf("PAN-TYPE for CVV on tagless domain model must be suppressed via negative evidence, got: %+v", f)
		}
	}
}

// TestDeferredSinks_PANScanner ( + scaffold): formalizes the
// phased-delivery contract. ships empty sink libraries for
// SinkHTTPResponse, SinkLoggerCall, and SinkCryptoCall — any FlowsTo query
// against these kinds returns false. /19 will populate them and add
// the real ERR-LEAK / PAN-LOGGER upgrades.
func TestDeferredSinks_PANScanner(t *testing.T) {
	t.Cleanup(taint.Reset)
	root := taintFixturePath(t, "transit")
	engine := taint.GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable in this environment (no go binary)")
	}

	src := taint.Source{
		Package:  "example.com/tainttransit/requests",
		TypeName: "TokenizeRequest",
		Field:    "CVV",
	}

	cases := []struct {
		name string
		kind taint.SinkKind
	}{
		{"SinkHTTPResponse ", taint.SinkHTTPResponse},
		{"SinkLoggerCall ", taint.SinkLoggerCall},
		{"SinkCryptoCall (deferred)", taint.SinkCryptoCall},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if engine.FlowsTo(src, taint.SinkPattern{Kind: tc.kind}) {
				t.Errorf("FlowsTo(%s) returned true; deferred sink library must stay empty in ", tc.name)
			}
		})
	}
}
