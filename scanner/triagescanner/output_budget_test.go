package triagescanner_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

// triageFixtureBudgetBytes is the acceptance budget on the golden
// because each finding embedded 20-30 lines of source via SurroundingCode;
// after the same fixture lands in the ~150 KB range (109 findings ×
// ~1.4 KB per finding = ResourceLink + Description + Suggestion + relative
// EvidenceFiles, no inline source).
//
// has fewer findings than the all-rule fixture, so the per-call payload
// shrinks proportionally.
const triageFixtureBudgetBytes = 240 * 1024

// triageFixturePerFindingBudgetBytes guards against per-finding source
// embedding regressions. A single finding should never carry more than ~2 KB
// of structured context — the ResourceLink + middleware + imports + notes
// payload is bounded by hand and well under this ceiling.
const triageFixturePerFindingBudgetBytes = 2 * 1024

// TestTriageOutputBudget asserts the triage_findings serialization budget on
// the canonical fixture. Guards against future regressions of
// SurroundingCode-style source embedding in FindingContext. Fixture
// is staged via the same copy helper as parity_test.go to bypass
// scanner.DefaultExcludeDirs "testdata" exclusion.
func TestTriageOutputBudget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}

	gen := reportscanner.NewReportGenerator(db)
	report, err := gen.GenerateWithOptions(ctx, scanRoot, "offline", false, true)
	if err != nil {
		t.Fatalf("GenerateWithOptions: %v", err)
	}
	if report == nil {
		t.Fatal("GenerateWithOptions returned nil report")
	}

	findings := make([]scanner.Finding, 0, len(report.Findings))
	for _, rf := range report.Findings {
		findings = append(findings, rf.Finding)
	}
	if len(findings) == 0 {
		t.Fatal("fixture report returned zero findings -- fixture or scanner regression")
	}

	engine := triagescanner.NewTriageEngine()
	result, err := engine.Triage(ctx, scanRoot, findings)
	if err != nil {
		t.Fatalf("TriageEngine.Triage: %v", err)
	}

	jsonBytes, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal triage result: %v", err)
	}

	totalSize := len(jsonBytes)
	if totalSize > triageFixtureBudgetBytes {
		// On budget breach: log the top-5 biggest findings so future
		// regressions surface the offending collector immediately.
		type sized struct {
			idx, size int
		}
		sizes := make([]sized, len(result.Findings))
		for i, ef := range result.Findings {
			eb, _ := json.Marshal(ef)
			sizes[i] = sized{i, len(eb)}
		}
		for i := 0; i < len(sizes); i++ {
			for j := i + 1; j < len(sizes); j++ {
				if sizes[j].size > sizes[i].size {
					sizes[i], sizes[j] = sizes[j], sizes[i]
				}
			}
		}
		topN := 5
		if topN > len(sizes) {
			topN = len(sizes)
		}
		for k := 0; k < topN; k++ {
			ef := result.Findings[sizes[k].idx]
			t.Logf("biggest[%d] size=%d rule=%s file=%s:%d notes=%d evidence=%d middleware=%d imports=%d",
				k, sizes[k].size, ef.Finding.RuleID, ef.Finding.FilePath, ef.Finding.Line,
				len(ef.Context.TriageNotes), len(ef.Context.EvidenceFiles),
				len(ef.Context.MiddlewareChain), len(ef.Context.Imports))
		}
		t.Fatalf(" budget breach: triage_findings fixture serialization is %d bytes (>%d budget). "+
			"Check that ResourceLink is not embedding source code and that no new bulk-context field was added.",
			totalSize, triageFixtureBudgetBytes)
	}

	avgPerFinding := totalSize / len(result.Findings)
	if avgPerFinding > triageFixturePerFindingBudgetBytes {
		t.Fatalf(" per-finding budget breach: %d bytes per finding (>%d budget). "+
			"Likely cause: a context collector started embedding source bytes again.",
			avgPerFinding, triageFixturePerFindingBudgetBytes)
	}

	t.Logf("triage_findings fixture size: total=%d bytes, findings=%d, avg=%d bytes/finding (budget %d total / %d per-finding)",
		totalSize, len(result.Findings), avgPerFinding, triageFixtureBudgetBytes, triageFixturePerFindingBudgetBytes)
}
