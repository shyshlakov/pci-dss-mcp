package hybridcache

import (
	"sort"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const MaxByRuleEntries = 10

type Histogram = scanner.ScannerSummary

func BuildHistogram(findings []scanner.Finding) Histogram {
	counts := scanner.CountBySeverity(findings)
	ruleCounts := map[string]int{}
	for _, f := range findings {
		ruleCounts[f.RuleID]++
	}
	hist := make([]scanner.RuleCount, 0, len(ruleCounts))
	for r, c := range ruleCounts {
		hist = append(hist, scanner.RuleCount{RuleID: r, Count: c})
	}
	sort.SliceStable(hist, func(i, j int) bool {
		if hist[i].Count != hist[j].Count {
			return hist[i].Count > hist[j].Count
		}
		return hist[i].RuleID < hist[j].RuleID
	})
	moreRules := 0
	if len(hist) > MaxByRuleEntries {
		moreRules = len(hist) - MaxByRuleEntries
		hist = hist[:MaxByRuleEntries]
	}
	return Histogram{
		BySeverity: scanner.SeverityStats{
			Critical: counts[scanner.SeverityCritical],
			High:     counts[scanner.SeverityHigh],
			Medium:   counts[scanner.SeverityMedium],
			Low:      counts[scanner.SeverityLow],
			Info:     counts[scanner.SeverityInfo],
		},
		ByRule:    hist,
		MoreRules: moreRules,
	}
}
