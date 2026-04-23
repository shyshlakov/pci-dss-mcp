package depscanner_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/shyshlakov/pci-dss-mcp/scanner/depscanner"
)

func newDepSessionForLayerB(t *testing.T) *mcp.ClientSession {
	t.Helper()
	server := mcp.NewServer(&mcp.Implementation{Name: "dep-layerb", Version: "v0.0.1"}, nil)
	depscanner.RegisterTools(server)
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(context.Background(), serverTransport, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}
	t.Cleanup(func() { _ = serverSession.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "dep-layerb-test-client", Version: "v0.0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func seedDepFixture(t *testing.T) string {
	t.Helper()

	projectDir := t.TempDir()
	srcGoMod := filepath.Join("..", "..", "testdata", "vulnerable.go.mod")
	data, err := os.ReadFile(srcGoMod)
	if err != nil {
		t.Fatalf("read go.mod fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), data, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	cacheDir := t.TempDir()
	t.Setenv("PCI_MCP_CACHE_DIR", cacheDir)

	vulns := map[string][]json.RawMessage{
		"golang.org/x/net": {
			rawVulnFixture("GHSA-test-net-1", "golang.org/x/net", "0", "0.23.0", "HIGH"),
			rawVulnFixture("GHSA-test-net-2", "golang.org/x/net", "0", "0.23.0", "CRITICAL"),
		},
		"golang.org/x/text": {
			rawVulnFixture("GHSA-test-text-1", "golang.org/x/text", "0", "0.15.0", "MEDIUM"),
		},
		"github.com/gin-gonic/gin": {
			rawVulnFixture("GHSA-test-gin-1", "github.com/gin-gonic/gin", "0", "1.10.0", "MEDIUM"),
		},
	}
	cacheDate := time.Now()
	dateStr := cacheDate.Format("2006-01-02")
	cachePath := filepath.Join(cacheDir, fmt.Sprintf("go-osv-%s.json", dateStr))
	cache := map[string]any{
		"generated":  cacheDate.UTC(),
		"source":     "test",
		"vuln_count": 4,
		"packages":   vulns,
	}
	cacheBytes, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("marshal cache: %v", err)
	}
	if err := os.WriteFile(cachePath, cacheBytes, 0o644); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	return projectDir
}

func rawVulnFixture(id, pkg, introduced, fixed, severity string) json.RawMessage {
	v := map[string]any{
		"id":      id,
		"summary": fmt.Sprintf("Test vulnerability %s", id),
		"aliases": []string{},
		"database_specific": map[string]string{
			"severity": severity,
		},
		"affected": []map[string]any{
			{
				"package": map[string]string{
					"name":      pkg,
					"ecosystem": "Go",
				},
				"ranges": []map[string]any{
					{
						"type": "SEMVER",
						"events": []map[string]string{
							{"introduced": introduced},
							{"fixed": fixed},
						},
					},
				},
			},
		},
	}
	data, _ := json.Marshal(v)
	return data
}

func callDepDefault(t *testing.T, session *mcp.ClientSession, path string) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": path,
			"mode": "offline",
		},
	})
	if err != nil {
		t.Fatalf("CallTool check_dependencies: %v", err)
	}
	if result.IsError {
		t.Fatalf("check_dependencies IsError: %+v", result)
	}
	return result
}

func depStructuredMap(t *testing.T, result *mcp.CallToolResult) map[string]any {
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

func TestDepLayerB_Default(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result := callDepDefault(t, session, projectDir)
	m := depStructuredMap(t, result)
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
}

func TestDepLayerB_TopNPerSeverity_Is1(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result := callDepDefault(t, session, projectDir)
	m := depStructuredMap(t, result)
	top := m["top_findings"].(map[string]any)
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		arr, _ := top[sev].([]any)
		if len(arr) > 1 {
			t.Errorf("top_findings[%q] len=%d, want <=1", sev, len(arr))
		}
	}
}

func TestDepLayerB_EmptyBucketsShipAsArray(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result := callDepDefault(t, session, projectDir)
	m := depStructuredMap(t, result)
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

func TestDepLayerB_Deterministic(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	r1 := callDepDefault(t, session, projectDir)
	r2 := callDepDefault(t, session, projectDir)
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

func TestDepLayerB_ByRuleHistogramSorted(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result := callDepDefault(t, session, projectDir)
	m := depStructuredMap(t, result)
	summary := m["summary"].(map[string]any)
	byRuleAny, ok := summary["by_rule"].([]any)
	if !ok {
		return
	}
	type hg struct {
		rule  string
		count int
	}
	hs := make([]hg, 0, len(byRuleAny))
	for _, e := range byRuleAny {
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

func TestDepLayerB_SizeBudget20KB(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result := callDepDefault(t, session, projectDir)
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 20480
	t.Logf("dep Layer B wire size on fixture = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("dep Layer B wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}

func TestDepLayerB_CursorRejectsQualityFilterCombo(t *testing.T) {
	session := newDepSessionForLayerB(t)
	tt := []struct {
		name string
		args map[string]any
	}{
		{
			"cursor+min_severity",
			map[string]any{
				"path":         ".",
				"cursor":       "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19kZXBlbmRlbmNpZXMifQ",
				"min_severity": "HIGH",
			},
		},
		{
			"cursor+rule_filter",
			map[string]any{
				"path":        ".",
				"cursor":      "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19kZXBlbmRlbmNpZXMifQ",
				"rule_filter": "DEP-VULN",
			},
		},
		{
			"cursor+positive_limit",
			map[string]any{
				"path":   ".",
				"cursor": "eyJzaWQiOiJhYmMiLCJvZmYiOjAsInRvb2wiOiJjaGVja19kZXBlbmRlbmNpZXMifQ",
				"limit":  10,
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "check_dependencies",
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

func TestDepLayerB_FilterSet_StillFlat(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path":         projectDir,
			"mode":         "offline",
			"min_severity": "MEDIUM",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("dep filter call IsError: %+v", result)
	}
	m := depStructuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Errorf("response_shape=%v, want flat (quality-filter path)", got)
	}
}

func TestDepLayerA_SizeBudget(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path":         projectDir,
			"mode":         "offline",
			"min_severity": "MEDIUM",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("check_dependencies Layer A returned IsError: %+v", result)
	}
	m := depStructuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Fatalf("response_shape=%v, want flat (min_severity forces Layer A)", got)
	}
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const budget = 20480
	t.Logf("dep Layer A wire size on fixture (min_severity=MEDIUM) = %d bytes (budget %d)", len(raw), budget)
	if len(raw) >= budget {
		t.Fatalf("dep Layer A wire size %d bytes exceeds budget %d", len(raw), budget)
	}
}

func TestDepToolDescription_SummaryFirstBias(t *testing.T) {
	session := newDepSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var desc string
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "check_dependencies" {
			continue
		}
		found = true
		desc = tool.Description
	}
	if !found {
		t.Fatalf("check_dependencies not in ListTools")
	}
	needles := []string{
		"summary",
		"cursor",
		"top 1 per severity",
	}
	for _, n := range needles {
		if !strings.Contains(desc, n) {
			t.Errorf("check_dependencies description missing substring %q; got: %s", n, desc)
		}
	}
}

func TestDepLayerB_MaxResultSizeChars(t *testing.T) {
	session := newDepSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "check_dependencies" {
			continue
		}
		found = true
		v, ok := tool.Meta["anthropic/maxResultSizeChars"]
		if !ok {
			t.Fatalf("check_dependencies Meta missing anthropic/maxResultSizeChars; got %+v", tool.Meta)
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
		t.Fatalf("check_dependencies not in ListTools")
	}
}

func TestDep_LimitMinusOneRejected(t *testing.T) {
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
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

func TestDep_InvalidModeRejected(t *testing.T) {
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path": ".",
			"mode": "invalid_mode",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true for invalid mode, got %+v", result)
	}
	var body string
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			body += tc.Text
		}
	}
	if !strings.Contains(body, "Invalid mode") {
		t.Errorf("error message missing 'Invalid mode'; got %q", body)
	}
}

func TestDep_InvalidModeRejectedBeforeLimit(t *testing.T) {
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path":  ".",
			"mode":  "bogus",
			"limit": -1,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true; got %+v", result)
	}
	var body string
	for _, c := range result.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			body += tc.Text
		}
	}
	if !strings.Contains(body, "Invalid mode") {
		t.Errorf("expected mode-whitelist guard to fire BEFORE limit=-1 reject; got %q", body)
	}
}

func TestDep_UpdateVulnDBStillRegistered(t *testing.T) {
	session := newDepSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name == "update_vulnerability_db" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("update_vulnerability_db tool MUST remain registered after migration")
	}
}

func TestDepLayerA_IncludesHistogram(t *testing.T) {
	projectDir := seedDepFixture(t)
	session := newDepSessionForLayerB(t)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "check_dependencies",
		Arguments: map[string]any{
			"path":         projectDir,
			"mode":         "offline",
			"min_severity": "HIGH",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("check_dependencies Layer A IsError: %+v", result)
	}
	m := depStructuredMap(t, result)
	if got := m["response_shape"]; got != "flat" {
		t.Fatalf("response_shape=%v, want flat", got)
	}
	summary, ok := m["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing: %T", m["summary"])
	}
	if _, ok := summary["by_severity"].(map[string]any); !ok {
		t.Fatalf("by_severity missing")
	}
	byRule, ok := summary["by_rule"].([]any)
	if !ok {
		t.Fatalf("by_rule wrong type: %T", summary["by_rule"])
	}
	if len(byRule) > 10 {
		t.Errorf("by_rule len=%d must be <=10", len(byRule))
	}
}

func TestDepToolDescription_LayerAHistogramNeedle(t *testing.T) {
	session := newDepSessionForLayerB(t)
	tools, err := session.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	var desc string
	var found bool
	for _, tool := range tools.Tools {
		if tool.Name != "check_dependencies" {
			continue
		}
		found = true
		desc = tool.Description
	}
	if !found {
		t.Fatalf("check_dependencies not in ListTools")
	}
	needles := []string{"summary.by_severity", "summary.by_rule", "full-scan"}
	for _, n := range needles {
		if !strings.Contains(desc, n) {
			t.Errorf("check_dependencies description missing substring %q", n)
		}
	}
}
