package taint_ssa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RuleMetrics captures recall and cost numbers for a single rule run.
type RuleMetrics struct {
	ASTFindings int   `json:"ast_findings"`
	SSAFindings int   `json:"ssa_findings"`
	ASTWallMs   int64 `json:"ast_wall_ms"`
	SSAWallMs   int64 `json:"ssa_wall_ms"`
}

// MemoryMetrics captures the peak HeapAlloc observed across both engine
// runs. The numbers are sampled via runtime.MemStats so they reflect Go
// heap usage only, not RSS.
type MemoryMetrics struct {
	ASTPeakBytes uint64 `json:"ast_peak_bytes"`
	SSAPeakBytes uint64 `json:"ssa_peak_bytes"`
}

// Metrics is the side-by-side measurement output written to
// baseline_metrics.json for the DECISION.md re-measurement step.
type Metrics struct {
	CapturedAt   string                 `json:"captured_at"`
	GitCommit    string                 `json:"git_commit"`
	Fixture      string                 `json:"fixture"`
	BuildStatus  string                 `json:"ssa_build_status"`
	BuildReason  string                 `json:"ssa_build_reason,omitempty"`
	BuildWallMs  int64                  `json:"ssa_build_wall_ms"`
	Rules        map[string]RuleMetrics `json:"rules"`
	Memory       MemoryMetrics          `json:"memory"`
	GoVersion    string                 `json:"go_version"`
	Architecture string                 `json:"architecture"`
}

// MeasurePARITY runs the SSA-based PAN-LOGGER and CRYPTO-HARDCODED-KEY
// rules against projectRoot and emits Metrics. The AST-side numbers are
// populated only when the caller supplies them via SetASTBaseline; the
// PoC keeps the AST measurement out of this package to preserve the
// import isolation contract (no scanner imports of internal/taint_ssa).
func MeasurePARITY(ctx context.Context, projectRoot string) (*Metrics, error) {
	m := &Metrics{
		CapturedAt:   time.Now().UTC().Format(time.RFC3339),
		GitCommit:    detectGitCommit(projectRoot),
		Fixture:      filepath.Base(projectRoot),
		BuildStatus:  "success",
		Rules:        map[string]RuleMetrics{},
		GoVersion:    runtime.Version(),
		Architecture: runtime.GOOS + "/" + runtime.GOARCH,
	}

	buildStart := time.Now()
	prog, err := BuildProgram(ctx, projectRoot)
	m.BuildWallMs = time.Since(buildStart).Milliseconds()

	if err != nil {
		m.BuildStatus = "failed"
		m.BuildReason = err.Error()
		m.Rules["PAN-LOGGER"] = RuleMetrics{}
		m.Rules["CRYPTO-HARDCODED-KEY"] = RuleMetrics{}
		return m, nil
	}
	if prog == nil {
		m.BuildStatus = "failed"
		m.BuildReason = "BuildProgram returned nil program"
		return m, nil
	}

	var msBefore runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&msBefore)

	panStart := time.Now()
	panFindings := RunPANLogger(prog)
	panWall := time.Since(panStart).Milliseconds()

	cryptoStart := time.Now()
	cryptoFindings := RunCryptoHardcodedKey(prog)
	cryptoWall := time.Since(cryptoStart).Milliseconds()

	var msAfter runtime.MemStats
	runtime.ReadMemStats(&msAfter)
	m.Memory.SSAPeakBytes = msAfter.HeapAlloc

	m.Rules["PAN-LOGGER"] = RuleMetrics{
		SSAFindings: len(panFindings),
		SSAWallMs:   panWall,
	}
	m.Rules["CRYPTO-HARDCODED-KEY"] = RuleMetrics{
		SSAFindings: len(cryptoFindings),
		SSAWallMs:   cryptoWall,
	}

	return m, nil
}

// SetASTBaseline lets a non-package caller record AST-side findings count
// and wall-clock for parity comparison. We do not call into internal/taint
// from here because that would create the very production-import coupling
// the plan forbids; the test harness in the parent project drives the AST
// engine and writes its numbers via this helper.
func (m *Metrics) SetASTBaseline(rule string, findings int, wallMs int64, peakBytes uint64) {
	if m == nil {
		return
	}
	r := m.Rules[rule]
	r.ASTFindings = findings
	r.ASTWallMs = wallMs
	m.Rules[rule] = r
	if peakBytes > m.Memory.ASTPeakBytes {
		m.Memory.ASTPeakBytes = peakBytes
	}
}

// WriteBaseline serializes m to path with stable indentation so diffs are
// easy to review.
func WriteBaseline(m *Metrics, path string) error {
	if m == nil {
		return fmt.Errorf("nil metrics")
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// detectGitCommit returns the short HEAD SHA of the repo containing root.
// Returns "unknown" if the lookup fails (no git binary, not a repo, etc.).
func detectGitCommit(root string) string {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--short", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}
