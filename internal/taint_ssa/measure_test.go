package taint_ssa_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint_ssa"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/panscanner"
)

func fixtureRootForMeasure(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "vulnerable-payment-service")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	return abs
}

func countFindingsByRule(findings []scanner.Finding, ruleID string) int {
	n := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			n++
		}
	}
	return n
}

func TestMeasurePARITY_WritesBaseline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping baseline measurement in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	root := fixtureRootForMeasure(t)

	m, err := taint_ssa.MeasurePARITY(ctx, root)
	if err != nil {
		t.Fatalf("MeasurePARITY: %v", err)
	}
	if m == nil {
		t.Fatal("MeasurePARITY returned nil metrics")
	}

	if m.BuildStatus == "success" {
		var msBefore runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&msBefore)

		panStart := time.Now()
		panResult, err := panscanner.New().ScanFullWithTaint(ctx, root, nil, false, false, true)
		panWall := time.Since(panStart).Milliseconds()
		panFindingsCount := 0
		if err == nil && panResult != nil {
			panFindingsCount = countFindingsByRule(panResult.Findings, "PAN-LOGGER")
		}

		cryptoStart := time.Now()
		cryptoResult, err := cryptoscanner.New().ScanFull(ctx, root, nil, false, false)
		cryptoWall := time.Since(cryptoStart).Milliseconds()
		cryptoFindingsCount := 0
		if err == nil && cryptoResult != nil {
			cryptoFindingsCount = countFindingsByRule(cryptoResult.Findings, "CRYPTO-HARDCODED-KEY")
		}

		var msAfter runtime.MemStats
		runtime.ReadMemStats(&msAfter)

		m.SetASTBaseline("PAN-LOGGER", panFindingsCount, panWall, msAfter.HeapAlloc)
		m.SetASTBaseline("CRYPTO-HARDCODED-KEY", cryptoFindingsCount, cryptoWall, msAfter.HeapAlloc)
	}

	outPath := filepath.Join(filepath.Dir(measureSourceFile(t)), "baseline_metrics.json")
	if err := taint_ssa.WriteBaseline(m, outPath); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var roundTrip taint_ssa.Metrics
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}
	if roundTrip.CapturedAt == "" {
		t.Error("baseline_metrics.json missing captured_at")
	}
	if _, ok := roundTrip.Rules["PAN-LOGGER"]; !ok {
		t.Error("baseline_metrics.json missing PAN-LOGGER rule")
	}
	if _, ok := roundTrip.Rules["CRYPTO-HARDCODED-KEY"]; !ok {
		t.Error("baseline_metrics.json missing CRYPTO-HARDCODED-KEY rule")
	}

	t.Logf("baseline written to %s", outPath)
	t.Logf("status=%s build_wall_ms=%d", roundTrip.BuildStatus, roundTrip.BuildWallMs)
	for rule, rm := range roundTrip.Rules {
		t.Logf("  %s ast=%d ssa=%d ast_ms=%d ssa_ms=%d",
			rule, rm.ASTFindings, rm.SSAFindings, rm.ASTWallMs, rm.SSAWallMs)
	}
	t.Logf("memory: ast_peak=%d ssa_peak=%d", roundTrip.Memory.ASTPeakBytes, roundTrip.Memory.SSAPeakBytes)
}

func measureSourceFile(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(1)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return thisFile
}

func TestMetricsWriteBaseline_Roundtrip(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "baseline_metrics.json")
	m := &taint_ssa.Metrics{
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
		GitCommit:   "test",
		Fixture:     "test",
		BuildStatus: "success",
		Rules: map[string]taint_ssa.RuleMetrics{
			"PAN-LOGGER":           {ASTFindings: 1, SSAFindings: 1, ASTWallMs: 100, SSAWallMs: 200},
			"CRYPTO-HARDCODED-KEY": {ASTFindings: 13, SSAFindings: 5, ASTWallMs: 50, SSAWallMs: 80},
		},
	}
	if err := taint_ssa.WriteBaseline(m, out); err != nil {
		t.Fatalf("WriteBaseline: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var rt taint_ssa.Metrics
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rt.Rules["PAN-LOGGER"].SSAFindings != 1 {
		t.Errorf("PAN-LOGGER ssa_findings = %d, want 1", rt.Rules["PAN-LOGGER"].SSAFindings)
	}
}

func TestMetricsWriteBaseline_NilErrors(t *testing.T) {
	tmp := t.TempDir()
	if err := taint_ssa.WriteBaseline(nil, filepath.Join(tmp, "x.json")); err == nil {
		t.Error("expected error for nil metrics")
	}
}
