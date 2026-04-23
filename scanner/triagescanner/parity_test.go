package triagescanner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/reportscanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

// TestTriageReportParity is the regression guard: triage_findings and
// generate_compliance_report MUST return the same active-finding count when
// invoked with default arguments. Before, triage_findings hardcoded
// includeTaint=false while generate_compliance_report defaulted to true after
// the gap stays closed.
//
// The assertion runs at three layers:
// 1. Direct reportscanner.GenerateWithOptions(..., includeTaint=true) finding count.
// 2. Direct triagescanner.TriageEngine.Triage on the same finding set, asserting
// the engine processes every finding (parity at the data layer).
// 3. End-to-end MCP tool handler call via in-memory transport with empty
// TriageInput (taint defaults ON), reading StructuredContent and asserting
// metadata.findings_total equals the report's active-finding count.
//
// After the tool returns StructuredContent + a 1-line text summary. The
// parity assertion now reads the structured payload directly via a typed
// json.Unmarshal instead of the legacy "JSON:\n..." text suffix.
func TestTriageReportParity(t *testing.T) {
	ctx := context.Background()

	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)

	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}

	// Layer 1: direct reportscanner with taint ON (the production default
	// after). offline dep mode keeps the test network-free.
	gen := reportscanner.NewReportGenerator(db)
	report, err := gen.GenerateWithOptions(ctx, scanRoot, "offline", false, true)
	if err != nil {
		t.Fatalf("GenerateWithOptions: %v", err)
	}
	if report == nil {
		t.Fatal("GenerateWithOptions returned nil report")
	}

	reportFindings := make([]scanner.Finding, 0, len(report.Findings))
	for _, rf := range report.Findings {
		reportFindings = append(reportFindings, rf.Finding)
	}
	reportTotal := len(reportFindings)
	if reportTotal == 0 {
		t.Fatal("fixture report returned zero findings -- fixture or scanner regression")
	}

	// triage engine skips verified-OK markers (AUDIT-LOG-OK, CSP-OK)
	// before enrichment to keep the MCP response small. The parity contract
	// is therefore: report_total == triage_enriched + verified_ok_count.
	// FindingsTotal metadata still reflects the original input count so the
	// client can see the delta. generate_compliance_report output is
	// unchanged — auditors still see verified-OK markers there.
	verifiedOKCount := 0
	for _, f := range reportFindings {
		if strings.HasSuffix(f.RuleID, "-OK") {
			verifiedOKCount++
		}
	}
	wantEnriched := reportTotal - verifiedOKCount

	// Layer 2: triage engine on the same finding set. FindingsTotal must
	// equal the input slice length (original count preserved). The
	// enriched Findings slice drops verified-OK markers.
	engine := triagescanner.NewTriageEngine()
	triageResult, err := engine.Triage(ctx, scanRoot, reportFindings)
	if err != nil {
		t.Fatalf("TriageEngine.Triage: %v", err)
	}
	if triageResult.Metadata.FindingsTotal != reportTotal {
		t.Fatalf(" parity broken at engine layer: triage FindingsTotal=%d, report had %d -- expected equal",
			triageResult.Metadata.FindingsTotal, reportTotal)
	}
	if len(triageResult.Findings) != wantEnriched {
		t.Fatalf(" parity broken at engine layer: triage emitted %d enriched findings, want %d (report=%d, verified-OK=%d)",
			len(triageResult.Findings), wantEnriched, reportTotal, verifiedOKCount)
	}

	// Layer 3: end-to-end MCP handler with empty TriageInput (taint defaults
	// ON via the new tri-state). Parse the StructuredContent payload
	// and compare metadata.findings_total to reportTotal. preserves
	// FindingsTotal as the original input count (not the enriched count)
	// so the client sees "triage received N, enriched M after skipping
	// K verified-OK" — parity at this layer stays reportTotal == handlerTotal.
	session := newTriageMCPSession(t, db)

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "triage_findings",
		Arguments: map[string]any{"path": scanRoot, "dep_scan_mode": "offline"},
	})
	if err != nil {
		t.Fatalf("triage_findings CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("triage_findings returned IsError: %s", firstTextContent(result))
	}

	handlerTotal := parseTriageStructuredTotal(t, result)
	if handlerTotal != reportTotal {
		t.Fatalf(" parity broken at MCP tool layer: triage_findings StructuredContent metadata.findings_total=%d, generate_compliance_report active=%d -- expected equal after taint default sync",
			handlerTotal, reportTotal)
	}
}

// newTriageMCPSession spins up an in-memory MCP server with the
// triage_findings tool and returns a connected client session. The server
// goroutine exits when the underlying transports are closed by t.Cleanup.
func newTriageMCPSession(t *testing.T, db *pcidb.DB) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "triage-parity", Version: "v0.0.1"}, nil)
	triagescanner.RegisterTools(server, db)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "parity-test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func firstTextContent(result *mcp.CallToolResult) string {
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

// parseTriageStructuredTotal reads metadata.findings_total from the
// CallToolResult.StructuredContent payload returned by triage_findings after
// . The SDK marshals the typed Out value (*TriageResult) into
// StructuredContent; on the client side after the JSON-RPC round-trip it
// surfaces as a generic map[string]any (or json.RawMessage when the SDK
// skips decoding), so we re-marshal whichever shape is present.
func parseTriageStructuredTotal(t *testing.T, result *mcp.CallToolResult) int {
	t.Helper()
	if result == nil {
		t.Fatal("nil CallToolResult")
	}
	if result.StructuredContent == nil {
		// "No active findings to triage" path returns an empty TriageResult,
		// not a nil StructuredContent — so a nil here is a real regression.
		t.Fatal("triage_findings StructuredContent is nil; expected typed Out value")
	}
	var raw []byte
	switch v := result.StructuredContent.(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal StructuredContent (%T): %v", v, err)
		}
		raw = b
	}
	var parsed struct {
		Metadata struct {
			FindingsTotal int `json:"findings_total"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("could not parse triage StructuredContent payload: %v", err)
	}
	return parsed.Metadata.FindingsTotal
}

// copyFixtureTreeForTriage mirrors reportscanner.copyFixtureTree (unexported
// in that package) so the parity test can stage the golden fixture outside
// the testdata/ path that scanner.DefaultExcludeDirs would otherwise skip.
func copyFixtureTreeForTriage(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %s: %w", path, walkErr)
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent %s: %w", target, err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("copyFixtureTreeForTriage(%s): %v", src, err)
	}
	return dst
}
