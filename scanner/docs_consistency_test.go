package scanner_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	severityRelFromScannerPkg    = "../docs/severity.md"
	pciCoverageRelFromScannerPkg = "../docs/pci-coverage.md"
	severityDynamicMarker        = "dynamic -- see docs/requirement-mapping.md"
)

type severityRow struct {
	ruleID      string
	severity    string
	requirement string
	description string
	isDynamic   bool
}

type pciCoverageRow struct {
	requirement string
	title       string
	scanners    []string
}

var (
	reqIDPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?$`)
	reqIDInText  = regexp.MustCompile(`\b\d+\.\d+\.\d+(\.\d+)?\b`)
)

func TestDocsConsistency(t *testing.T) {
	t.Parallel()
	canonical := loadDocsTable(t)
	severity := loadSeverityTable(t)
	coverage := loadPciCoverageTable(t)

	t.Run("severity_rules_exist_in_canonical", func(tt *testing.T) {
		checkSeverityInCanonical(severity, canonical, tt.Errorf)
	})

	t.Run("severity_static_primary_matches_canonical", func(tt *testing.T) {
		checkSeverityPrimaryMatches(severity, canonical, tt.Errorf)
	})

	t.Run("severity_dynamic_annotation_present_for_dynamic_canonical_rules", func(tt *testing.T) {
		checkSeverityDynamicAnnotation(severity, canonical, tt.Errorf)
	})

	t.Run("pci_coverage_requirements_appear_in_canonical", func(tt *testing.T) {
		checkCoverageInCanonical(coverage, canonical, tt.Errorf)
	})
}

func TestDocsConsistencySyntheticDrift(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name       string
		severity   map[string]severityRow
		canonical  map[string]docsRow
		coverage   map[string]pciCoverageRow
		check      func(map[string]severityRow, map[string]pciCoverageRow, map[string]docsRow, func(string, ...any))
		wantErrors int
		wantSubstr string
	}{
		{
			name:      "severity_rule_missing_from_canonical",
			severity:  map[string]severityRow{"RULE-X": {ruleID: "RULE-X", requirement: "3.5.1"}},
			canonical: map[string]docsRow{},
			check: func(s map[string]severityRow, _ map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkSeverityInCanonical(s, c, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-X",
		},
		{
			name:      "static_primary_mismatch",
			severity:  map[string]severityRow{"RULE-Y": {ruleID: "RULE-Y", requirement: "8.3.1"}},
			canonical: map[string]docsRow{"RULE-Y": {ruleID: "RULE-Y", primary: "8.6.2"}},
			check: func(s map[string]severityRow, _ map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkSeverityPrimaryMatches(s, c, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-Y",
		},
		{
			name:      "dynamic_canonical_but_static_severity",
			severity:  map[string]severityRow{"RULE-Z": {ruleID: "RULE-Z", requirement: "3.5.1", isDynamic: false}},
			canonical: map[string]docsRow{"RULE-Z": {ruleID: "RULE-Z", primary: "3.5.1", coverageNote: "dynamic emit helper"}},
			check: func(s map[string]severityRow, _ map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkSeverityDynamicAnnotation(s, c, r)
			},
			wantErrors: 1,
			wantSubstr: "RULE-Z",
		},
		{
			name:      "dynamic_match",
			severity:  map[string]severityRow{"RULE-W": {ruleID: "RULE-W", requirement: "3.5.1 or 3.3.1", isDynamic: true}},
			canonical: map[string]docsRow{"RULE-W": {ruleID: "RULE-W", primary: "3.5.1", coverageNote: "dynamic emit helper"}},
			check: func(s map[string]severityRow, _ map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkSeverityDynamicAnnotation(s, c, r)
			},
			wantErrors: 0,
		},
		{
			name:      "coverage_requirement_orphan",
			canonical: map[string]docsRow{"RULE-V": {ruleID: "RULE-V", primary: "9.9.9"}},
			coverage:  map[string]pciCoverageRow{"1.1.1": {requirement: "1.1.1"}},
			check: func(_ map[string]severityRow, cov map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkCoverageInCanonical(cov, c, r)
			},
			wantErrors: 1,
			wantSubstr: "1.1.1",
		},
		{
			name:      "coverage_requirement_reachable_via_coverage_note_waiver",
			canonical: map[string]docsRow{"PAN-KEYWORD": {ruleID: "PAN-KEYWORD", primary: "3.5.1", coverageNote: "dynamic emit -- PAN-classified field routes to 3.5.1; SAD-classified routes to 3.3.1 via sensitivedata.Classify"}},
			coverage:  map[string]pciCoverageRow{"3.3.1": {requirement: "3.3.1"}},
			check: func(_ map[string]severityRow, cov map[string]pciCoverageRow, c map[string]docsRow, r func(string, ...any)) {
				checkCoverageInCanonical(cov, c, r)
			},
			wantErrors: 0,
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(tt *testing.T) {
			var errs []string
			c.check(c.severity, c.coverage, c.canonical, func(format string, args ...any) {
				errs = append(errs, fmt.Sprintf(format, args...))
			})
			if len(errs) != c.wantErrors {
				tt.Fatalf("got %d errors, want %d (errors: %v)", len(errs), c.wantErrors, errs)
			}
			if c.wantSubstr != "" && (len(errs) == 0 || !strings.Contains(errs[0], c.wantSubstr)) {
				tt.Fatalf("want error to contain %q, got %v", c.wantSubstr, errs)
			}
		})
	}
}

func loadSeverityTable(t *testing.T) map[string]severityRow {
	t.Helper()
	path := filepath.Join(scannerDir(t), severityRelFromScannerPkg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	rows := map[string]severityRow{}
	inTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			inTable = false
			continue
		}
		if strings.Contains(trimmed, "| Rule ID |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if strings.HasPrefix(trimmed, "|--") || strings.HasPrefix(trimmed, "|-") {
			continue
		}
		cells := splitTableRow(trimmed)
		if len(cells) < 4 {
			continue
		}
		ruleID := strings.TrimSpace(cells[0])
		if ruleID == "" || ruleID == "Rule ID" {
			continue
		}
		req := strings.TrimSpace(cells[2])
		row := severityRow{
			ruleID:      ruleID,
			severity:    strings.TrimSpace(cells[1]),
			requirement: req,
			description: strings.TrimSpace(cells[3]),
			isDynamic:   strings.Contains(req, severityDynamicMarker),
		}
		if prev, dup := rows[ruleID]; dup {
			if prev.requirement == row.requirement {
				continue
			}
			t.Errorf("docs/severity.md: duplicate row for rule_id %q with differing Requirement columns (%q vs %q)", ruleID, prev.requirement, row.requirement)
			continue
		}
		rows[ruleID] = row
	}
	if len(rows) == 0 {
		t.Fatalf("docs/severity.md: parsed zero rule rows")
	}
	return rows
}

func loadPciCoverageTable(t *testing.T) map[string]pciCoverageRow {
	t.Helper()
	path := filepath.Join(scannerDir(t), pciCoverageRelFromScannerPkg)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s): %v", path, err)
	}
	rows := map[string]pciCoverageRow{}
	inTable := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			inTable = false
			continue
		}
		if strings.Contains(trimmed, "| Requirement |") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if strings.HasPrefix(trimmed, "|--") || strings.HasPrefix(trimmed, "|-") {
			continue
		}
		cells := splitTableRow(trimmed)
		if len(cells) < 3 {
			continue
		}
		req := strings.TrimSpace(cells[0])
		if req == "" || req == "Requirement" {
			continue
		}
		if !reqIDPattern.MatchString(req) {
			continue
		}
		scanners := []string{}
		for _, s := range strings.Split(cells[2], ",") {
			if ss := strings.TrimSpace(s); ss != "" {
				scanners = append(scanners, ss)
			}
		}
		rows[req] = pciCoverageRow{
			requirement: req,
			title:       strings.TrimSpace(cells[1]),
			scanners:    scanners,
		}
	}
	if len(rows) == 0 {
		t.Fatalf("docs/pci-coverage.md: parsed zero rows")
	}
	return rows
}

func checkSeverityInCanonical(sev map[string]severityRow, canon map[string]docsRow, report func(string, ...any)) {
	ids := make([]string, 0, len(sev))
	for id := range sev {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := canon[id]; !ok {
			report("severity.md rule %q has no row in docs/requirement-mapping.md", id)
		}
	}
}

func checkSeverityPrimaryMatches(sev map[string]severityRow, canon map[string]docsRow, report func(string, ...any)) {
	ids := make([]string, 0, len(sev))
	for id := range sev {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := sev[id]
		canonRow, ok := canon[id]
		if !ok {
			continue
		}
		if row.isDynamic {
			continue
		}
		if strings.Contains(canonRow.coverageNote, dynamicEmitWaiver) {
			continue
		}
		if row.requirement != canonRow.primary {
			report("severity.md rule %q requirement=%q but canonical primary=%q", id, row.requirement, canonRow.primary)
		}
	}
}

func checkSeverityDynamicAnnotation(sev map[string]severityRow, canon map[string]docsRow, report func(string, ...any)) {
	ids := make([]string, 0, len(sev))
	for id := range sev {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		row := sev[id]
		canonRow, ok := canon[id]
		if !ok {
			continue
		}
		canonicalIsDynamic := strings.Contains(canonRow.coverageNote, dynamicEmitWaiver)
		if canonicalIsDynamic && !row.isDynamic {
			report("severity.md rule %q canonical entry is dynamic but severity.md row shows static requirement %q (expected 'or' + '%s' annotation)", id, row.requirement, severityDynamicMarker)
		}
	}
}

func checkCoverageInCanonical(coverage map[string]pciCoverageRow, canon map[string]docsRow, report func(string, ...any)) {
	reqs := make([]string, 0, len(coverage))
	for r := range coverage {
		reqs = append(reqs, r)
	}
	sort.Strings(reqs)
	canonicalRequirements := map[string]bool{}
	for _, c := range canon {
		if c.primary != "" {
			canonicalRequirements[c.primary] = true
		}
		for _, rel := range c.related {
			if rel != "" {
				canonicalRequirements[rel] = true
			}
		}
		for _, m := range reqIDInText.FindAllString(c.coverageNote, -1) {
			canonicalRequirements[m] = true
		}
	}
	for _, req := range reqs {
		if !canonicalRequirements[req] {
			report("pci-coverage.md requirement %q is not referenced as primary, related, or dynamic-emit target in docs/requirement-mapping.md", req)
		}
	}
}
