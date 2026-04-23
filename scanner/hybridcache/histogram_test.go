package hybridcache_test

import (
	"encoding/json"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/hybridcache"
)

func mkFinding(rule string, sev scanner.Severity) scanner.Finding {
	return scanner.Finding{RuleID: rule, Severity: sev}
}

func TestBuildHistogram_SortsCountDescRuleIDAsc(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{
		mkFinding("RULE-B", scanner.SeverityHigh),
		mkFinding("RULE-A", scanner.SeverityHigh),
		mkFinding("RULE-C", scanner.SeverityMedium),
		mkFinding("RULE-A", scanner.SeverityHigh),
		mkFinding("RULE-B", scanner.SeverityHigh),
		mkFinding("RULE-A", scanner.SeverityHigh),
	}
	hist := hybridcache.BuildHistogram(findings)
	if len(hist.ByRule) != 3 {
		t.Fatalf("len(ByRule)=%d want 3", len(hist.ByRule))
	}
	if hist.ByRule[0].RuleID != "RULE-A" || hist.ByRule[0].Count != 3 {
		t.Errorf("ByRule[0]=%+v want {RULE-A, 3}", hist.ByRule[0])
	}
	if hist.ByRule[1].RuleID != "RULE-B" || hist.ByRule[1].Count != 2 {
		t.Errorf("ByRule[1]=%+v want {RULE-B, 2}", hist.ByRule[1])
	}
	if hist.ByRule[2].RuleID != "RULE-C" || hist.ByRule[2].Count != 1 {
		t.Errorf("ByRule[2]=%+v want {RULE-C, 1}", hist.ByRule[2])
	}
	if hist.MoreRules != 0 {
		t.Errorf("MoreRules=%d want 0", hist.MoreRules)
	}
}

func TestBuildHistogram_Top10CapWithOverflow(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{}
	rules := []string{
		"R-01", "R-02", "R-03", "R-04", "R-05",
		"R-06", "R-07", "R-08", "R-09", "R-10",
		"R-11", "R-12", "R-13",
	}
	for i, r := range rules {
		for j := 0; j <= i; j++ {
			findings = append(findings, mkFinding(r, scanner.SeverityHigh))
		}
	}
	hist := hybridcache.BuildHistogram(findings)
	if len(hist.ByRule) != 10 {
		t.Fatalf("len(ByRule)=%d want 10 (top-10 cap)", len(hist.ByRule))
	}
	if hist.MoreRules != 3 {
		t.Errorf("MoreRules=%d want 3 (13 rules - 10 cap)", hist.MoreRules)
	}
	if hist.ByRule[0].RuleID != "R-13" || hist.ByRule[0].Count != 13 {
		t.Errorf("ByRule[0]=%+v want {R-13, 13}", hist.ByRule[0])
	}
}

func TestBuildHistogram_ExactlyTenRules_NoMoreRules(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{}
	for i := 1; i <= 10; i++ {
		findings = append(findings, mkFinding("R-"+string(rune('A'+i-1)), scanner.SeverityHigh))
	}
	hist := hybridcache.BuildHistogram(findings)
	if len(hist.ByRule) != 10 {
		t.Errorf("len(ByRule)=%d want 10", len(hist.ByRule))
	}
	if hist.MoreRules != 0 {
		t.Errorf("MoreRules=%d want 0 when exactly 10 rules", hist.MoreRules)
	}
}

func TestBuildHistogram_BySeverityCounts(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{
		mkFinding("R-1", scanner.SeverityCritical),
		mkFinding("R-2", scanner.SeverityCritical),
		mkFinding("R-3", scanner.SeverityHigh),
		mkFinding("R-4", scanner.SeverityHigh),
		mkFinding("R-5", scanner.SeverityHigh),
		mkFinding("R-6", scanner.SeverityMedium),
		mkFinding("R-7", scanner.SeverityLow),
		mkFinding("R-8", scanner.SeverityInfo),
		mkFinding("R-9", scanner.SeverityInfo),
		mkFinding("R-10", scanner.SeverityInfo),
		mkFinding("R-11", scanner.SeverityInfo),
	}
	hist := hybridcache.BuildHistogram(findings)
	if hist.BySeverity.Critical != 2 {
		t.Errorf("Critical=%d want 2", hist.BySeverity.Critical)
	}
	if hist.BySeverity.High != 3 {
		t.Errorf("High=%d want 3", hist.BySeverity.High)
	}
	if hist.BySeverity.Medium != 1 {
		t.Errorf("Medium=%d want 1", hist.BySeverity.Medium)
	}
	if hist.BySeverity.Low != 1 {
		t.Errorf("Low=%d want 1", hist.BySeverity.Low)
	}
	if hist.BySeverity.Info != 4 {
		t.Errorf("Info=%d want 4", hist.BySeverity.Info)
	}
}

func TestBuildHistogram_EmptySlice_NoPanic(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		in   []scanner.Finding
	}{
		{"nil", nil},
		{"empty", []scanner.Finding{}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			hist := hybridcache.BuildHistogram(tc.in)
			if hist.BySeverity.Critical != 0 || hist.BySeverity.High != 0 ||
				hist.BySeverity.Medium != 0 || hist.BySeverity.Low != 0 ||
				hist.BySeverity.Info != 0 {
				t.Errorf("BySeverity=%+v want zero", hist.BySeverity)
			}
			if len(hist.ByRule) != 0 {
				t.Errorf("len(ByRule)=%d want 0", len(hist.ByRule))
			}
			if hist.MoreRules != 0 {
				t.Errorf("MoreRules=%d want 0", hist.MoreRules)
			}
		})
	}
}

func TestBuildHistogram_Deterministic(t *testing.T) {
	t.Parallel()
	findings := []scanner.Finding{
		mkFinding("PAN-KEYWORD", scanner.SeverityHigh),
		mkFinding("PAN-KEYWORD", scanner.SeverityHigh),
		mkFinding("PAN-TYPE", scanner.SeverityMedium),
		mkFinding("AUTH-MISSING-MFA", scanner.SeverityCritical),
		mkFinding("AUTH-MISSING-MFA", scanner.SeverityCritical),
		mkFinding("AUTH-MISSING-MFA", scanner.SeverityCritical),
	}
	first, err := json.Marshal(hybridcache.BuildHistogram(findings))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 100; i++ {
		next, err := json.Marshal(hybridcache.BuildHistogram(findings))
		if err != nil {
			t.Fatalf("marshal iter %d: %v", i, err)
		}
		if string(first) != string(next) {
			t.Fatalf("histogram non-deterministic at iter %d:\nfirst=%s\nnext =%s", i, first, next)
		}
	}
}
