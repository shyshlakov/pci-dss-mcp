package sqlscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

type dropCase struct {
	name      string
	files     map[string]string
	findings  []scanner.Finding
	metas     []sqlFindingMeta
	want      []scanner.Severity
	wantHints []string
}

func TestApplyMigrationDropDowngrade(t *testing.T) {
	t.Parallel()
	makeFinding := func(rule, path, col string, sev scanner.Severity) scanner.Finding {
		return scanner.Finding{
			RuleID:            rule,
			Severity:          sev,
			FilePath:          path,
			Line:              3,
			Confidence:        "high",
			SQLPatternMatched: true,
		}
	}

	run := func(t *testing.T, tc dropCase) {
		t.Helper()
		tmp := t.TempDir()
		migDir := filepath.Join(tmp, "migrations")
		if err := os.MkdirAll(migDir, 0o755); err != nil {
			t.Fatalf("mkdir migrations: %v", err)
		}
		writeFiles(t, migDir, tc.files)

		resolved := make([]scanner.Finding, len(tc.findings))
		for i, f := range tc.findings {
			f.FilePath = filepath.Join(migDir, f.FilePath)
			resolved[i] = f
		}

		out := applyMigrationDropDowngrade(resolved, tc.metas, 0, len(resolved))
		if len(out) != len(tc.want) {
			t.Fatalf("%s: findings len=%d want %d", tc.name, len(out), len(tc.want))
		}
		for i := range out {
			if out[i].Severity != tc.want[i] {
				t.Errorf("%s: finding[%d] severity=%s want %s", tc.name, i, out[i].Severity, tc.want[i])
			}
			if i < len(tc.wantHints) && tc.wantHints[i] != "" {
				if !strings.HasPrefix(out[i].TriageHint, tc.wantHints[i]) {
					t.Errorf("%s: finding[%d] TriageHint=%q want prefix %q", tc.name, i, out[i].TriageHint, tc.wantHints[i])
				}
			}
		}
	}

	runNonMig := func(t *testing.T, tc dropCase) {
		t.Helper()
		tmp := t.TempDir()
		subDir := filepath.Join(tmp, "schema")
		if err := os.MkdirAll(subDir, 0o755); err != nil {
			t.Fatalf("mkdir schema: %v", err)
		}
		writeFiles(t, subDir, tc.files)

		resolved := make([]scanner.Finding, len(tc.findings))
		for i, f := range tc.findings {
			f.FilePath = filepath.Join(subDir, f.FilePath)
			resolved[i] = f
		}

		out := applyMigrationDropDowngrade(resolved, tc.metas, 0, len(resolved))
		for i := range out {
			if out[i].Severity != tc.want[i] {
				t.Errorf("%s: finding[%d] severity=%s want %s", tc.name, i, out[i].Severity, tc.want[i])
			}
		}
	}

	cases := []dropCase{
		{
			name: "case1_drop_downgrades",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE t DROP COLUMN IF EXISTS pan;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
				makeFinding(RuleSQLTextType, "20240101000000_add.sql", "pan", scanner.SeverityMedium),
			},
			metas: []sqlFindingMeta{
				{TableName: "t", ColumnName: "pan"},
				{TableName: "t", ColumnName: "pan"},
			},
			want: []scanner.Severity{scanner.SeverityInfo, scanner.SeverityInfo},
			wantHints: []string{
				"downgrade:column_dropped_in_20260101000000_drop",
				"downgrade:column_dropped_in_20260101000000_drop",
			},
		},
		{
			name: "case2_readd_preserves_high",
			files: map[string]string{
				"20240101000000_add.sql":   "CREATE TABLE t (pan TEXT);",
				"20260101000000_drop.sql":  "ALTER TABLE t DROP COLUMN pan;",
				"20260301000000_readd.sql": "ALTER TABLE t ADD COLUMN pan TEXT;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		},
		{
			name: "case3_single_file_no_downgrade",
			files: map[string]string{
				"20240101000000_add.sql": "CREATE TABLE t (pan TEXT);",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		},
		{
			name: "case4_non_timestamp_aborts_dir",
			files: map[string]string{
				"init.sql":        "CREATE TABLE t (pan TEXT);",
				"001_add_pan.sql": "ALTER TABLE t DROP COLUMN pan;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "init.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		},
		{
			name: "case5_different_column_drop",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT, cvv TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE t DROP COLUMN cvv;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		},
		{
			name: "case7_comma_terminated_drop",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT, cvv TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE t DROP COLUMN pan, DROP COLUMN cvv;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityInfo},
			wantHints: []string{
				"downgrade:column_dropped_in_20260101000000_drop",
			},
		},
		{
			name: "case8_case_insensitive_match",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE T DROP COLUMN PAN;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityInfo},
		},
		{
			name: "case9_alter_add_without_column_keyword",
			files: map[string]string{
				"20240101000000_add.sql":   "CREATE TABLE t (pan TEXT);",
				"20260101000000_drop.sql":  "ALTER TABLE t DROP COLUMN pan;",
				"20260301000000_readd.sql": "ALTER TABLE t ADD pan TEXT NOT NULL;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		},
		{
			name: "case10_metaidx_alignment_mixed_rules",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT, cvv TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE t DROP COLUMN pan;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
				makeFinding(RuleSQLTextType, "20240101000000_add.sql", "pan", scanner.SeverityMedium),
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "cvv", scanner.SeverityHigh),
				makeFinding(RuleSQLTextType, "20240101000000_add.sql", "cvv", scanner.SeverityMedium),
			},
			metas: []sqlFindingMeta{
				{TableName: "t", ColumnName: "pan"},
				{TableName: "t", ColumnName: "pan"},
				{TableName: "t", ColumnName: "cvv"},
				{TableName: "t", ColumnName: "cvv"},
			},
			// no metaIdx alignment bug — mixed SQL-SENSITIVE-COLUMN and SQL-TEXT-TYPE findings paired 1:1 with sqlMetas, alignment preserved
			want: []scanner.Severity{
				scanner.SeverityInfo,
				scanner.SeverityInfo,
				scanner.SeverityHigh,
				scanner.SeverityMedium,
			},
		},
		{
			name: "case11_3digit_golang_migrate_regex",
			files: map[string]string{
				"001_create.sql": "CREATE TABLE t (pan TEXT);",
				"002_drop.sql":   "ALTER TABLE t DROP COLUMN pan;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "001_create.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityInfo},
			wantHints: []string{
				"downgrade:column_dropped_in_002_drop",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) { run(t, tc) })
	}

	t.Run("case6_path_not_migrations", func(t *testing.T) {
		runNonMig(t, dropCase{
			name: "case6",
			files: map[string]string{
				"20240101000000_add.sql":  "CREATE TABLE t (pan TEXT);",
				"20260101000000_drop.sql": "ALTER TABLE t DROP COLUMN pan;",
			},
			findings: []scanner.Finding{
				makeFinding(RuleSQLSensitiveColumn, "20240101000000_add.sql", "pan", scanner.SeverityHigh),
			},
			metas: []sqlFindingMeta{{TableName: "t", ColumnName: "pan"}},
			want:  []scanner.Severity{scanner.SeverityHigh},
		})
	})
}

func TestIsMigrationDir(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"foo/migrations/bar", true},
		{"/a/migrations/b", true},
		{"foo/migration/bar", true},
		{"foo/bar/migrations", true},
		{"foo/bar/migration", true},
		{"foo/MIGRATIONS/bar", true},
		{"foo/schema/bar", false},
		{"migrations_foo/bar", false},
	}
	for _, tc := range cases {
		if got := isMigrationDir(tc.in); got != tc.want {
			t.Errorf("isMigrationDir(%q) = %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestListOrderedMigrationFilesAbortsOnNonTimestamp(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "init.sql"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "001_add.sql"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := listOrderedMigrationFiles(tmp); ok {
		t.Errorf("expected abort on non-timestamp file, got ok=true")
	}
}
