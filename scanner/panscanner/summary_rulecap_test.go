package panscanner

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

func synthPANFindingsVaryingCounts(t *testing.T) []scanner.Finding {
	t.Helper()
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityInfo,
	}
	out := make([]scanner.Finding, 0, 120)
	for i := 0; i < 15; i++ {
		ruleID := fmt.Sprintf("PAN-RULE-%02d", i)
		count := 15 - i
		for j := 0; j < count; j++ {
			sev := severities[(i+j)%len(severities)]
			out = append(out, scanner.Finding{
				RuleID:   ruleID,
				Severity: sev,
				FilePath: fmt.Sprintf("f%02d_%02d.go", i, j),
				Line:     j + 1,
			})
		}
	}
	return out
}

func marshalPANSummaryToMap(t *testing.T, resp *PANSummaryResponse) map[string]any {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return m
}

func TestPANLayerB_ByRuleCap_15Rules(t *testing.T) {
	findings := synthPANFindingsVaryingCounts(t)
	resp := buildPANSummaryInternal(findings, hybridcache.ScanMeta{}, "sid-test", "")
	m := marshalPANSummaryToMap(t, resp)
	summary, ok := m["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary missing: %T", m["summary"])
	}
	byRule, ok := summary["by_rule"].([]any)
	if !ok {
		t.Fatalf("by_rule missing: %T", summary["by_rule"])
	}
	if got := len(byRule); got != 10 {
		t.Fatalf("len(by_rule)=%d, want 10", got)
	}
	moreRaw, ok := summary["more_rules"]
	if !ok {
		t.Fatalf("summary.more_rules missing from serialized JSON (want 5)")
	}
	var more int
	switch v := moreRaw.(type) {
	case float64:
		more = int(v)
	case int:
		more = v
	default:
		t.Fatalf("summary.more_rules unexpected type %T", moreRaw)
	}
	if more != 5 {
		t.Fatalf("summary.more_rules=%d, want 5", more)
	}
	for i := 0; i < len(byRule)-1; i++ {
		a := byRule[i].(map[string]any)
		b := byRule[i+1].(map[string]any)
		ca, _ := a["count"].(float64)
		cb, _ := b["count"].(float64)
		if ca < cb {
			t.Fatalf("by_rule not sorted count desc at %d: %v vs %v", i, a, b)
		}
	}
	retained := map[string]int{}
	for _, e := range byRule {
		em := e.(map[string]any)
		id, _ := em["rule_id"].(string)
		cnt, _ := em["count"].(float64)
		retained[id] = int(cnt)
	}
	for i := 0; i < 10; i++ {
		ruleID := fmt.Sprintf("PAN-RULE-%02d", i)
		wantCount := 15 - i
		if got, ok := retained[ruleID]; !ok {
			t.Errorf("retained set missing %s (want count=%d)", ruleID, wantCount)
		} else if got != wantCount {
			t.Errorf("retained[%s]=%d, want %d", ruleID, got, wantCount)
		}
	}
}
