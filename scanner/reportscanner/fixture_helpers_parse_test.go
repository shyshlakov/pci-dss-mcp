package reportscanner

import (
	"reflect"
	"testing"
)

func TestParseBodyTables(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name           string
		lines          []string
		wantViolations []expectedFinding
		wantClean      []string
	}{
		{
			name: "legacy_5_col_row",
			lines: []string{
				"## Violations",
				"| Rule ID | Severity | File | Line | Notes |",
				"|---------|----------|------|------|-------|",
				"| PAN-KEYWORD | HIGH | foo/bar.go | 9 | note text |",
			},
			wantViolations: []expectedFinding{
				{
					RuleID:              "PAN-KEYWORD",
					Severity:            "HIGH",
					FilePath:            "foo/bar.go",
					Line:                9,
					RequirementID:       "",
					RelatedRequirements: nil,
					Notes:               "note text",
				},
			},
		},
		{
			name: "new_7_col_row_full",
			lines: []string{
				"## Violations",
				"| Rule ID | Severity | File | Line | Req ID | Related | Notes |",
				"|---------|----------|------|------|--------|---------|-------|",
				"| PAN-KEYWORD | HIGH | foo/bar.go | 9 | 3.5.1 | 3.4.1, 10.2.1 | note text |",
			},
			wantViolations: []expectedFinding{
				{
					RuleID:              "PAN-KEYWORD",
					Severity:            "HIGH",
					FilePath:            "foo/bar.go",
					Line:                9,
					RequirementID:       "3.5.1",
					RelatedRequirements: []string{"3.4.1", "10.2.1"},
					Notes:               "note text",
				},
			},
		},
		{
			name: "new_7_col_row_empty_reqs",
			lines: []string{
				"## Violations",
				"| Rule ID | Severity | File | Line | Req ID | Related | Notes |",
				"|---------|----------|------|------|--------|---------|-------|",
				"| AUDIT-LOG-OK | INFO | foo/bar.go | 11 |  |  | logrus fields |",
			},
			wantViolations: []expectedFinding{
				{
					RuleID:              "AUDIT-LOG-OK",
					Severity:            "INFO",
					FilePath:            "foo/bar.go",
					Line:                11,
					RequirementID:       "",
					RelatedRequirements: nil,
					Notes:               "logrus fields",
				},
			},
		},
		{
			name: "new_7_col_row_single_related",
			lines: []string{
				"## Violations",
				"| Rule ID | Severity | File | Line | Req ID | Related | Notes |",
				"|---------|----------|------|------|--------|---------|-------|",
				"| AUTH-HARDCODED-PWD | CRITICAL | internal/auth/admin.go | 3 | 8.6.2 | 8.3.1 | admin pw |",
			},
			wantViolations: []expectedFinding{
				{
					RuleID:              "AUTH-HARDCODED-PWD",
					Severity:            "CRITICAL",
					FilePath:            "internal/auth/admin.go",
					Line:                3,
					RequirementID:       "8.6.2",
					RelatedRequirements: []string{"8.3.1"},
					Notes:               "admin pw",
				},
			},
		},
		{
			name: "malformed_row_skipped",
			lines: []string{
				"## Violations",
				"| Rule ID | Severity | File | Line | Notes |",
				"|---------|----------|------|------|-------|",
				"| ONLY | TWO |",
				"| PAN-KEYWORD | HIGH | foo/bar.go | 9 | note |",
			},
			wantViolations: []expectedFinding{
				{
					RuleID:   "PAN-KEYWORD",
					Severity: "HIGH",
					FilePath: "foo/bar.go",
					Line:     9,
					Notes:    "note",
				},
			},
		},
		{
			name: "clean_section",
			lines: []string{
				"## Clean (must NOT be flagged)",
				"| File | Reason |",
				"|------|--------|",
				"| internal/foo.go | safe |",
			},
			wantClean: []string{"internal/foo.go"},
		},
	}

	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			gotV, gotC := parseBodyTables(c.lines)
			if !reflect.DeepEqual(gotV, c.wantViolations) {
				t.Errorf("violations: want %#v got %#v", c.wantViolations, gotV)
			}
			if !reflect.DeepEqual(gotC, c.wantClean) {
				t.Errorf("clean: want %#v got %#v", c.wantClean, gotC)
			}
		})
	}
}

func TestParseRelatedList(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"spaces_only", "   ", nil},
		{"single", "8.6.2", []string{"8.6.2"}},
		{"multi", "3.4.1, 10.2.1", []string{"3.4.1", "10.2.1"}},
		{"trailing_comma", "3.3.1.2,", []string{"3.3.1.2"}},
		{"extra_spaces", "  3.3.1 ,  3.3.1.2  ", []string{"3.3.1", "3.3.1.2"}},
	}
	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			got := parseRelatedList(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("want %#v got %#v", c.want, got)
			}
		})
	}
}

func TestEqualStringSetsIgnoreOrder(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		a, b []string
		want bool
	}{
		{"both_empty", nil, nil, true},
		{"same_order", []string{"a", "b"}, []string{"a", "b"}, true},
		{"diff_order", []string{"a", "b"}, []string{"b", "a"}, true},
		{"diff_len", []string{"a"}, []string{"a", "b"}, false},
		{"disjoint", []string{"a"}, []string{"b"}, false},
		{"dup_vs_unique", []string{"a", "a"}, []string{"a", "b"}, false},
	}
	for _, c := range tt {
		t.Run(c.name, func(t *testing.T) {
			if got := equalStringSetsIgnoreOrder(c.a, c.b); got != c.want {
				t.Errorf("want %v got %v", c.want, got)
			}
		})
	}
}
