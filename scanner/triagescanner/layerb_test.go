package triagescanner_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/pcidb"
	"github.com/shyshlakov/pci-dss-mcp/scanner/triagescanner"
)

func newTriageSessionForLayerB(t *testing.T, db *pcidb.DB) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "triage-layerb", Version: "v0.0.1"}, nil)
	triagescanner.RegisterTools(server, db)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() {
		_ = server.Run(context.Background(), serverTransport)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "layerb-test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func callTriageDefault(t *testing.T, path string) *mcp.CallToolResult {
	t.Helper()
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	session := newTriageSessionForLayerB(t, db)
	includeTaint := true
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "triage_findings",
		Arguments: map[string]any{
			"path":          path,
			"dep_scan_mode": "offline",
			"include_taint": includeTaint,
		},
	})
	if err != nil {
		t.Fatalf("CallTool triage_findings: %v", err)
	}
	if result.IsError {
		t.Fatalf("triage_findings returned IsError: %+v", result)
	}
	return result
}

func structuredMap(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal StructuredContent: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal StructuredContent: %v", err)
	}
	return m
}

func TestTriageLayerB_Default(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	result := callTriageDefault(t, scanRoot)
	m := structuredMap(t, result)
	if got := m["response_shape"]; got != "summary" {
		t.Fatalf("response_shape=%v, want summary", got)
	}
	if _, ok := m["top_findings"].(map[string]any); !ok {
		t.Fatalf("top_findings missing or wrong type: %T", m["top_findings"])
	}
	summary, ok := m["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing: %T", m["summary"])
	}
	bySev, ok := summary["by_severity"].(map[string]any)
	if !ok {
		t.Fatalf("by_severity missing: %T", summary["by_severity"])
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := bySev[sev]; !ok {
			t.Errorf("by_severity[%q] missing", sev)
		}
	}
	byRule, ok := summary["by_rule"].([]any)
	if !ok || len(byRule) == 0 {
		t.Fatalf("by_rule empty or wrong type: %T %d", summary["by_rule"], len(byRule))
	}
	pag, ok := m["pagination"].(map[string]any)
	if !ok {
		t.Fatalf("pagination missing")
	}
	if cur, _ := pag["next_cursor"].(string); cur == "" {
		t.Errorf("next_cursor empty; expected cursor for drill-down")
	}
}

func TestTriageLayerB_TopNPerSeverity_Is2(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	result := callTriageDefault(t, scanRoot)
	m := structuredMap(t, result)
	top, ok := m["top_findings"].(map[string]any)
	if !ok {
		t.Fatalf("top_findings missing")
	}
	for _, sev := range []string{"critical", "high", "medium", "info"} {
		arr, _ := top[sev].([]any)
		if len(arr) > 2 {
			t.Errorf("top_findings[%q] len=%d, want <=2", sev, len(arr))
		}
	}
	if lowArr, _ := top["low"].([]any); len(lowArr) != 0 {
		t.Errorf("top_findings[\"low\"] expected empty (fixture has LOW=0), got len=%d", len(lowArr))
	}
}

func TestTriageLayerB_Deterministic(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	r1 := callTriageDefault(t, scanRoot)
	r2 := callTriageDefault(t, scanRoot)
	m1, _ := json.Marshal(r1.StructuredContent)
	m2, _ := json.Marshal(r2.StructuredContent)
	var s1, s2 map[string]any
	if err := json.Unmarshal(m1, &s1); err != nil {
		t.Fatalf("unmarshal r1: %v", err)
	}
	if err := json.Unmarshal(m2, &s2); err != nil {
		t.Fatalf("unmarshal r2: %v", err)
	}
	t1, _ := json.Marshal(s1["top_findings"])
	t2, _ := json.Marshal(s2["top_findings"])
	if string(t1) != string(t2) {
		t.Errorf("top_findings not deterministic across runs:\nrun1: %s\nrun2: %s", string(t1), string(t2))
	}
}

func TestTriageLayerB_ByRuleHistogramSorted(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	result := callTriageDefault(t, scanRoot)
	m := structuredMap(t, result)
	summary := m["summary"].(map[string]any)
	byRule := summary["by_rule"].([]any)
	type hg struct {
		rule  string
		count int
	}
	hs := make([]hg, 0, len(byRule))
	for _, e := range byRule {
		em := e.(map[string]any)
		cnt := 0
		switch v := em["count"].(type) {
		case float64:
			cnt = int(v)
		case int:
			cnt = v
		}
		hs = append(hs, hg{rule: em["rule_id"].(string), count: cnt})
	}
	if !sort.SliceIsSorted(hs, func(i, j int) bool {
		if hs[i].count != hs[j].count {
			return hs[i].count > hs[j].count
		}
		return hs[i].rule < hs[j].rule
	}) {
		t.Errorf("by_rule not sorted count desc, rule_id asc: %+v", hs)
	}
}

func TestTriageLayerB_SizeBudget20KB(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	result := callTriageDefault(t, scanRoot)
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 20480
	t.Logf("triage Layer B wire size on golden fixture = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("triage Layer B wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}

func TestTriageLayerB_CursorRejectsFilterCombo(t *testing.T) {
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	session := newTriageSessionForLayerB(t, db)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "triage_findings",
		Arguments: map[string]any{
			"cursor":       "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJ0cmlhZ2VfZmluZGluZ3MifQ",
			"min_severity": "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true for cursor+filter combo, got %+v", result)
	}
}

func TestTriageLayerB_FilterSet_StillFlat(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForTriage(t, fixtureRoot)
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	session := newTriageSessionForLayerB(t, db)
	includeTaint := true
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "triage_findings",
		Arguments: map[string]any{
			"path":          scanRoot,
			"dep_scan_mode": "offline",
			"min_severity":  "HIGH",
			"include_taint": includeTaint,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("triage_findings filtered returned IsError: %+v", result)
	}
	m := structuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Errorf("response_shape=%v, want flat (filtered call)", got)
	}
}

func TestTriageLayerB_MaxResultSizeChars(t *testing.T) {
	db, err := pcidb.New()
	if err != nil {
		t.Fatalf("pcidb.New: %v", err)
	}
	session := newTriageSessionForLayerB(t, db)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "triage_findings" {
			continue
		}
		found = true
		v, ok := tool.Meta["anthropic/maxResultSizeChars"]
		if !ok {
			t.Fatalf("triage_findings Meta missing anthropic/maxResultSizeChars; got %+v", tool.Meta)
		}
		got := int64(0)
		switch x := v.(type) {
		case int:
			got = int64(x)
		case int64:
			got = x
		case float64:
			got = int64(x)
		default:
			t.Fatalf("anthropic/maxResultSizeChars unexpected type %T value %v", v, v)
		}
		if got != 20000 {
			t.Errorf("anthropic/maxResultSizeChars=%d want 20000", got)
		}
	}
	if !found {
		t.Fatalf("triage_findings not in ListTools")
	}
}
