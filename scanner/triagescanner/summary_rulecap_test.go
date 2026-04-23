package triagescanner

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

func synthTriageEnrichedVaryingCounts(t *testing.T) []EnrichedFinding {
	t.Helper()
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityInfo,
	}
	out := make([]EnrichedFinding, 0, 120)
	for i := 0; i < 15; i++ {
		ruleID := fmt.Sprintf("RULE-%02d", i)
		count := 15 - i
		for j := 0; j < count; j++ {
			sev := severities[(i+j)%len(severities)]
			out = append(out, EnrichedFinding{
				Finding: scanner.Finding{
					RuleID:   ruleID,
					Severity: sev,
					FilePath: fmt.Sprintf("f%02d_%02d.go", i, j),
					Line:     j + 1,
				},
			})
		}
	}
	return out
}

func marshalTriageSummaryToMap(t *testing.T, resp *TriageSummaryResponse) map[string]any {
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

func TestTriageLayerB_ByRuleCap_15Rules(t *testing.T) {
	t.Parallel()
	enriched := synthTriageEnrichedVaryingCounts(t)
	resp := buildTriageSummaryInternal(
		enriched,
		TriageLayerBMetadata{FindingsTotal: len(enriched)},
		hybridcache.ScanMeta{},
		len(enriched),
		"sid-test",
		"",
	)
	m := marshalTriageSummaryToMap(t, resp)
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
		ruleID := fmt.Sprintf("RULE-%02d", i)
		wantCount := 15 - i
		if got, ok := retained[ruleID]; !ok {
			t.Errorf("retained set missing %s (want count=%d)", ruleID, wantCount)
		} else if got != wantCount {
			t.Errorf("retained[%s]=%d, want %d", ruleID, got, wantCount)
		}
	}
}

func TestTriageLayerB_SyntheticVariance_12Rules(t *testing.T) {
	t.Parallel()
	severities := []scanner.Severity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityInfo,
	}
	enriched := make([]EnrichedFinding, 0, 24)
	for i := 0; i < 12; i++ {
		ruleID := fmt.Sprintf("RULE-%02d", i)
		for j := 0; j < 2; j++ {
			sev := severities[(i+j)%len(severities)]
			enriched = append(enriched, EnrichedFinding{
				Finding: scanner.Finding{
					RuleID:        ruleID,
					Severity:      sev,
					FilePath:      fmt.Sprintf("f%02d_%02d.go", i, j),
					Line:          j + 1,
					Description:   "synthetic finding for variance test",
					Suggestion:    "irrelevant",
					RequirementID: "3.3.1",
				},
				Hint: "synthetic enrichment hint",
			})
		}
	}
	resp := buildTriageSummaryInternal(
		enriched,
		TriageLayerBMetadata{FindingsTotal: len(enriched), FindingsTriaged: len(enriched)},
		hybridcache.ScanMeta{},
		len(enriched),
		"sid-test",
		"",
	)
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	t.Logf("synthetic 12-rule triage Layer B wire size = %d bytes", len(raw))
	if len(raw) >= 15000 {
		t.Fatalf("synthetic 12-rule triage Layer B %d bytes exceeds 15000 B guard", len(raw))
	}
}
