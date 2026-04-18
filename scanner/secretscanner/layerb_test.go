package secretscanner_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
)

func newSecretSessionForLayerB(t *testing.T) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "secret-layerb", Version: "v0.0.1"}, nil)
	secretscanner.RegisterTools(server)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	go func() {
		_ = server.Run(context.Background(), serverTransport)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "secret-layerb-test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func copyFixtureTreeForSecret(t *testing.T, srcRoot string) string {
	t.Helper()
	abs, err := filepath.Abs(srcRoot)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return abs
}

func callSecretDefault(t *testing.T, path string) *mcp.CallToolResult {
	t.Helper()
	session := newSecretSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
		Arguments: map[string]any{
			"path": path,
		},
	})
	if err != nil {
		t.Fatalf("CallTool check_secrets_in_configs: %v", err)
	}
	if result.IsError {
		t.Fatalf("check_secrets_in_configs IsError: %+v", result)
	}
	return result
}

func secretStructuredMap(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func TestSecretLayerB_Default(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	result := callSecretDefault(t, scanRoot)
	m := secretStructuredMap(t, result)
	if got := m["response_shape"]; got != "summary" {
		t.Fatalf("response_shape=%v, want summary", got)
	}
	if _, ok := m["top_findings"].(map[string]any); !ok {
		t.Fatalf("top_findings missing or wrong type: %T", m["top_findings"])
	}
	summary, ok := m["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing")
	}
	if _, ok := summary["by_severity"].(map[string]any); !ok {
		t.Fatalf("by_severity missing")
	}
	byRule, ok := summary["by_rule"].([]any)
	if !ok || len(byRule) == 0 {
		t.Fatalf("by_rule empty/wrong type: %T len=%d", summary["by_rule"], len(byRule))
	}
}

func TestSecretLayerB_TopNPerSeverity_Is3(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	result := callSecretDefault(t, scanRoot)
	m := secretStructuredMap(t, result)
	top := m["top_findings"].(map[string]any)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		arr, _ := top[sev].([]any)
		if len(arr) > 3 {
			t.Errorf("top_findings[%q] len=%d, want <=3", sev, len(arr))
		}
	}
}

func TestSecretLayerB_EmptyBucketsShipAsArray(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	result := callSecretDefault(t, scanRoot)
	m := secretStructuredMap(t, result)
	top := m["top_findings"].(map[string]any)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		v, present := top[sev]
		if !present {
			t.Fatalf("top_findings[%q] key missing; empty bucket MUST ship as [] not omitted", sev)
		}
		if _, ok := v.([]any); !ok {
			t.Fatalf("top_findings[%q] wrong type: %T", sev, v)
		}
	}
}

func TestSecretLayerB_Deterministic(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	r1 := callSecretDefault(t, scanRoot)
	r2 := callSecretDefault(t, scanRoot)
	b1, _ := json.Marshal(r1.StructuredContent)
	b2, _ := json.Marshal(r2.StructuredContent)
	var s1, s2 map[string]any
	if err := json.Unmarshal(b1, &s1); err != nil {
		t.Fatalf("unmarshal s1: %v", err)
	}
	if err := json.Unmarshal(b2, &s2); err != nil {
		t.Fatalf("unmarshal s2: %v", err)
	}
	t1, _ := json.Marshal(s1["top_findings"])
	t2, _ := json.Marshal(s2["top_findings"])
	if string(t1) != string(t2) {
		t.Errorf("top_findings non-deterministic:\n%s\n%s", string(t1), string(t2))
	}
}

func TestSecretLayerB_ByRuleHistogramSorted(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	result := callSecretDefault(t, scanRoot)
	m := secretStructuredMap(t, result)
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
		if v, ok := em["count"].(float64); ok {
			cnt = int(v)
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

func TestSecretLayerB_SizeBudget20KB(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	result := callSecretDefault(t, scanRoot)
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 20480
	t.Logf("secret Layer B wire size on golden fixture = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("secret Layer B wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}

func TestSecretLayerB_CursorRejectsFilterCombo(t *testing.T) {
	session := newSecretSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
		Arguments: map[string]any{
			"cursor":        "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19zZWNyZXRzX2luX2NvbmZpZ3MifQ",
			"include_tests": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError on cursor+filter combo; got %+v", result)
	}
}

func TestSecretLayerB_CursorRejectsQualityFilterCombo(t *testing.T) {
	session := newSecretSessionForLayerB(t)
	tt := []struct {
		name string
		args map[string]any
	}{
		{
			"cursor+min_severity",
			map[string]any{
				"cursor":       "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19zZWNyZXRzX2luX2NvbmZpZ3MifQ",
				"min_severity": "HIGH",
			},
		},
		{
			"cursor+rule_filter",
			map[string]any{
				"cursor":      "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19zZWNyZXRzX2luX2NvbmZpZ3MifQ",
				"rule_filter": "SEC-PREFIX",
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "check_secrets_in_configs",
				Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected IsError=true for %s; got %+v", tc.name, result)
			}
		})
	}
}

func TestSecretLayerB_FilterSet_StillFlat(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	session := newSecretSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
		Arguments: map[string]any{
			"path":          scanRoot,
			"include_tests": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	m := secretStructuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Errorf("response_shape=%v, want flat (scope-filter path)", got)
	}
}

func TestSecretLayerA_SizeBudget(t *testing.T) {
	fixtureRoot := filepath.Join("..", "..", "testdata", "vulnerable-payment-service")
	scanRoot := copyFixtureTreeForSecret(t, fixtureRoot)
	session := newSecretSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
		Arguments: map[string]any{
			"path":          scanRoot,
			"include_tests": true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("check_secrets_in_configs Layer A returned IsError: %+v", result)
	}
	m := secretStructuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Fatalf("response_shape=%v, want flat (include_tests=true forces Layer A)", got)
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 20480
	t.Logf("secret Layer A wire size on golden fixture (include_tests=true) = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("secret Layer A wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}

func TestSecretToolDescription_SummaryFirstBias(t *testing.T) {
	session := newSecretSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var desc string
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "check_secrets_in_configs" {
			continue
		}
		found = true
		desc = tool.Description
	}
	if !found {
		t.Fatalf("check_secrets_in_configs not in ListTools")
	}
	needles := []string{
		"summary",
		"cursor",
		"top 3 per severity",
	}
	for _, n := range needles {
		if !strings.Contains(desc, n) {
			t.Errorf("check_secrets_in_configs description missing substring %q; got: %s", n, desc)
		}
	}
}

func TestSecretLayerB_MaxResultSizeChars(t *testing.T) {
	session := newSecretSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "check_secrets_in_configs" {
			continue
		}
		found = true
		v, ok := tool.Meta["anthropic/maxResultSizeChars"]
		if !ok {
			t.Fatalf("check_secrets_in_configs Meta missing anthropic/maxResultSizeChars; got %+v", tool.Meta)
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
		t.Fatalf("check_secrets_in_configs not in ListTools")
	}
}

func TestSecret_LimitMinusOneRejected(t *testing.T) {
	session := newSecretSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_secrets_in_configs",
		Arguments: map[string]any{
			"path":  ".",
			"limit": -1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true for limit=-1, got %+v", result)
	}
	var body string
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			body += tc.Text
		}
	}
	if !strings.Contains(body, "LIMIT_MINUS_ONE_REMOVED") {
		t.Errorf("error message missing LIMIT_MINUS_ONE_REMOVED code; got %q", body)
	}
}
