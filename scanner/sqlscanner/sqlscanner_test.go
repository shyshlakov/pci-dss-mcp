package sqlscanner_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/sqlscanner"
)

func TestSQLScanner_Name(t *testing.T) {
	t.Parallel()
	s := sqlscanner.New()
	if got, want := s.Name(), "sql_schema"; got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestSQLScanner_Requirements(t *testing.T) {
	t.Parallel()
	s := sqlscanner.New()
	reqs := s.Requirements()
	want := map[string]bool{"3.3.1": false, "3.5.1": false}
	for _, r := range reqs {
		if _, ok := want[r]; !ok {
			t.Errorf("unexpected requirement %q", r)
			continue
		}
		want[r] = true
	}
	for r, seen := range want {
		if !seen {
			t.Errorf("missing requirement %q", r)
		}
	}
}

// copyFixture copies one or more source files into a fresh temp dir so the
// scanner can walk them (walker excludes testdata/ directories).
func copyFixtures(t *testing.T, sources ...string) string {
	t.Helper()
	tmp := t.TempDir()
	for _, src := range sources {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		dst := filepath.Join(tmp, filepath.Base(src))
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}
	return tmp
}

func TestSQLScanner_ScanMigrations(t *testing.T) {
	t.Parallel()
	posSrc := filepath.Join("testdata", "migrations", "positive.sql")
	if _, err := os.Stat(posSrc); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	tmp := copyFixtures(t, posSrc)

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("expected findings from positive.sql, got zero")
	}

	sawSensitive := false
	sawTextType := false
	for _, f := range result.Findings {
		if !strings.HasSuffix(f.FilePath, ".sql") {
			t.Errorf("unexpected non-sql FilePath %q", f.FilePath)
		}
		if f.Line <= 0 {
			t.Errorf("%s: Line = %d, want > 0", f.RuleID, f.Line)
		}
		if f.Description == "" {
			t.Errorf("%s: empty Description", f.RuleID)
		}
		if f.Suggestion == "" {
			t.Errorf("%s: empty Suggestion", f.RuleID)
		}
		switch f.RuleID {
		case sqlscanner.RuleSQLSensitiveColumn:
			sawSensitive = true
			if f.Severity != scanner.SeverityHigh {
				t.Errorf("SQL-SENSITIVE-COLUMN severity = %q, want HIGH", f.Severity)
			}
			if f.RequirementID != "3.5.1" && f.RequirementID != "3.3.1" {
				t.Errorf("SQL-SENSITIVE-COLUMN req = %q, want 3.3.1 or 3.5.1", f.RequirementID)
			}
		case sqlscanner.RuleSQLTextType:
			sawTextType = true
			if f.Severity != scanner.SeverityMedium {
				t.Errorf("SQL-TEXT-TYPE severity = %q, want MEDIUM", f.Severity)
			}
			if f.RequirementID != "3.5.1" {
				t.Errorf("SQL-TEXT-TYPE req = %q, want 3.5.1", f.RequirementID)
			}
		}
	}
	if !sawSensitive {
		t.Error("expected at least one SQL-SENSITIVE-COLUMN finding")
	}
	if !sawTextType {
		t.Error("expected at least one SQL-TEXT-TYPE finding")
	}

	// Negative fixture yields zero findings.
	negSrc := filepath.Join("testdata", "migrations", "negative.sql")
	negTmp := copyFixtures(t, negSrc)
	negRes, err := s.ScanFull(context.Background(), negTmp, nil, false, true)
	if err != nil {
		t.Fatalf("Scan negative: %v", err)
	}
	if len(negRes.Findings) != 0 {
		t.Errorf("expected 0 findings on negative.sql, got %d: %+v", len(negRes.Findings), negRes.Findings)
	}
}

// TestSQLScanner_ContextAwareSQL verifies that scanSQLFile uses context-aware matching:
// cards.number fires, users.number does NOT fire.
func TestSQLScanner_ContextAwareSQL(t *testing.T) {
	t.Parallel()
	src := filepath.Join("testdata", "migrations", "context_aware.sql")
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	tmp := copyFixtures(t, src)

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// cards.number should fire SQL-SENSITIVE-COLUMN + SQL-TEXT-TYPE.
	sawCardsNumber := false
	sawCardsNumberTextType := false
	// cards.verification_code from ALTER TABLE should fire.
	sawVerificationCode := false
	for _, f := range result.Findings {
		desc := strings.ToLower(f.Description)
		if f.RuleID == sqlscanner.RuleSQLSensitiveColumn && strings.Contains(desc, "\"number\"") {
			sawCardsNumber = true
		}
		if f.RuleID == sqlscanner.RuleSQLTextType && strings.Contains(desc, "\"number\"") {
			sawCardsNumberTextType = true
		}
		if f.RuleID == sqlscanner.RuleSQLSensitiveColumn && strings.Contains(desc, "\"verification_code\"") {
			sawVerificationCode = true
		}
		// users.number and users.account must NOT fire.
		if strings.Contains(desc, "users") {
			t.Errorf("unexpected finding on users table: %+v", f)
		}
	}
	if !sawCardsNumber {
		t.Error("expected SQL-SENSITIVE-COLUMN for cards.number")
	}
	if !sawCardsNumberTextType {
		t.Error("expected SQL-TEXT-TYPE for cards.number")
	}
	if !sawVerificationCode {
		t.Error("expected SQL-SENSITIVE-COLUMN for cards.verification_code")
	}
}

// TestSQLScanner_ContextAwareGorm_Encrypted verifies card_encrypted.go:
// Number -> INFO (encrypted), no ExpMonth/ExpYear findings (panProtected=true, ).
func TestSQLScanner_ContextAwareGorm_Encrypted(t *testing.T) {
	t.Parallel()
	src := filepath.Join("testdata", "models", "card_encrypted.go")
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	tmp := copyFixtures(t, src)

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Should have exactly 1 GORM-SENSITIVE-TAG (Number at INFO).
	// No findings for ExpMonth/ExpYear.
	sensitiveTagCount := 0
	for _, f := range result.Findings {
		if f.RuleID == sqlscanner.RuleGormSensitiveTag {
			sensitiveTagCount++
			if f.Severity != scanner.SeverityInfo {
				t.Errorf("card_encrypted.go GORM-SENSITIVE-TAG severity = %q, want INFO", f.Severity)
			}
			if !strings.Contains(f.Description, "Number") {
				t.Errorf("expected Number in description, got: %s", f.Description)
			}
		}
		if f.RuleID == sqlscanner.RuleGormNoEncryptHook {
			t.Errorf("unexpected GORM-NO-ENCRYPT-HOOK on card_encrypted.go")
		}
	}
	if sensitiveTagCount != 1 {
		t.Errorf("expected 1 GORM-SENSITIVE-TAG on card_encrypted.go, got %d", sensitiveTagCount)
		for _, f := range result.Findings {
			t.Logf("  finding: %s %s %s", f.RuleID, f.Severity, f.Description)
		}
	}
}

// TestSQLScanner_ContextAwareGorm_NoEncrypt verifies card_no_encrypt.go:
// Number -> HIGH, ExpMonth -> MEDIUM, ExpYear -> MEDIUM.
func TestSQLScanner_ContextAwareGorm_NoEncrypt(t *testing.T) {
	t.Parallel()
	src := filepath.Join("testdata", "models", "card_no_encrypt.go")
	if _, err := os.Stat(src); err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	tmp := copyFixtures(t, src)

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Should have 3 GORM-SENSITIVE-TAG + 1 GORM-NO-ENCRYPT-HOOK.
	type findingKey struct {
		field    string
		severity scanner.Severity
	}
	found := map[findingKey]bool{}
	for _, f := range result.Findings {
		if f.RuleID == sqlscanner.RuleGormSensitiveTag {
			if strings.Contains(f.Description, "Number") {
				found[findingKey{"Number", f.Severity}] = true
			}
			if strings.Contains(f.Description, "ExpMonth") {
				found[findingKey{"ExpMonth", f.Severity}] = true
			}
			if strings.Contains(f.Description, "ExpYear") {
				found[findingKey{"ExpYear", f.Severity}] = true
			}
		}
	}
	wantFindings := []findingKey{
		{"Number", scanner.SeverityHigh},
		{"ExpMonth", scanner.SeverityMedium},
		{"ExpYear", scanner.SeverityMedium},
	}
	for _, w := range wantFindings {
		if !found[w] {
			t.Errorf("expected GORM-SENSITIVE-TAG for %s at %s, not found", w.field, w.severity)
		}
	}
	// Also expect GORM-NO-ENCRYPT-HOOK.
	sawNoHook := false
	for _, f := range result.Findings {
		if f.RuleID == sqlscanner.RuleGormNoEncryptHook {
			sawNoHook = true
		}
	}
	if !sawNoHook {
		t.Error("expected GORM-NO-ENCRYPT-HOOK on card_no_encrypt.go")
	}
}

func TestSQLScanner_ScanGormModels(t *testing.T) {
	t.Parallel()
	withHookSrc := filepath.Join("testdata", "models", "with_hook.go")
	withoutHookSrc := filepath.Join("testdata", "models", "without_hook.go")
	if _, err := os.Stat(withHookSrc); err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	// Without-hook fixture: both GORM-SENSITIVE-TAG (HIGH) and
	// GORM-NO-ENCRYPT-HOOK (HIGH) must fire.
	tmpNo := copyFixtures(t, withoutHookSrc)
	s := sqlscanner.New()
	resNo, err := s.ScanFull(context.Background(), tmpNo, nil, false, true)
	if err != nil {
		t.Fatalf("Scan without_hook: %v", err)
	}
	sawTag, sawNoHook := false, false
	for _, f := range resNo.Findings {
		switch f.RuleID {
		case sqlscanner.RuleGormSensitiveTag:
			sawTag = true
			if f.Severity != scanner.SeverityHigh {
				t.Errorf("without_hook GORM-SENSITIVE-TAG severity = %q, want HIGH", f.Severity)
			}
		case sqlscanner.RuleGormNoEncryptHook:
			sawNoHook = true
			if f.Severity != scanner.SeverityHigh {
				t.Errorf("GORM-NO-ENCRYPT-HOOK severity = %q, want HIGH", f.Severity)
			}
			if f.RequirementID != "3.5.1" {
				t.Errorf("GORM-NO-ENCRYPT-HOOK req = %q, want 3.5.1", f.RequirementID)
			}
		}
	}
	if !sawTag {
		t.Error("expected GORM-SENSITIVE-TAG on without_hook.go")
	}
	if !sawNoHook {
		t.Error("expected GORM-NO-ENCRYPT-HOOK on without_hook.go")
	}

	// With-hook fixture: GORM-SENSITIVE-TAG downgraded to INFO;
	// no GORM-NO-ENCRYPT-HOOK.
	tmpYes := copyFixtures(t, withHookSrc)
	resYes, err := s.ScanFull(context.Background(), tmpYes, nil, false, true)
	if err != nil {
		t.Fatalf("Scan with_hook: %v", err)
	}
	sawInfo := false
	for _, f := range resYes.Findings {
		if f.RuleID == sqlscanner.RuleGormNoEncryptHook {
			t.Errorf("unexpected GORM-NO-ENCRYPT-HOOK on with_hook.go: %+v", f)
		}
		if f.RuleID == sqlscanner.RuleGormSensitiveTag {
			sawInfo = true
			if f.Severity != scanner.SeverityInfo {
				t.Errorf("with_hook GORM-SENSITIVE-TAG severity = %q, want INFO ", f.Severity)
			}
			if f.RequirementID != "3.5.1" && f.RequirementID != "3.3.1" {
				t.Errorf("GORM-SENSITIVE-TAG req = %q, want 3.3.1 or 3.5.1", f.RequirementID)
			}
		}
	}
	if !sawInfo {
		t.Error("expected at least one GORM-SENSITIVE-TAG on with_hook.go (downgraded to INFO)")
	}
}

// TestSQLExpiryExemption verifies: exp_month/exp_year are suppressed in SQL
// findings when PAN in the same table is protected (bytea), but kept when PAN is
// unprotected (text). Non-expiry sensitive columns (like cvv) are never suppressed.
func TestSQLExpiryExemption(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		sql        string
		wantRules  map[string]bool // rule+col key -> should be present
		wantAbsent map[string]bool // rule+col key -> must NOT be present
	}{
		{
			name: "PAN_bytea_suppresses_expiry",
			sql: `CREATE TABLE cards (
    id uuid PRIMARY KEY,
    number bytea,
    exp_month bigint,
    exp_year bigint
);`,
			wantRules: map[string]bool{
				"SQL-SENSITIVE-COLUMN:number": true,
			},
			wantAbsent: map[string]bool{
				"SQL-SENSITIVE-COLUMN:exp_month": true,
				"SQL-SENSITIVE-COLUMN:exp_year":  true,
			},
		},
		{
			name: "PAN_text_keeps_expiry",
			sql: `CREATE TABLE cards (
    id uuid PRIMARY KEY,
    number text,
    exp_month bigint,
    exp_year bigint
);`,
			wantRules: map[string]bool{
				"SQL-SENSITIVE-COLUMN:number":    true,
				"SQL-SENSITIVE-COLUMN:exp_month": true,
				"SQL-SENSITIVE-COLUMN:exp_year":  true,
			},
			wantAbsent: map[string]bool{},
		},
		{
			name: "PAN_bytea_cvv_kept_expiry_suppressed",
			sql: `CREATE TABLE cards (
    id uuid PRIMARY KEY,
    number bytea,
    cvv text,
    exp_month bigint
);`,
			wantRules: map[string]bool{
				"SQL-SENSITIVE-COLUMN:cvv": true,
			},
			wantAbsent: map[string]bool{
				"SQL-SENSITIVE-COLUMN:exp_month": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			sqlPath := filepath.Join(tmp, "migration.sql")
			if err := os.WriteFile(sqlPath, []byte(tt.sql), 0o644); err != nil {
				t.Fatal(err)
			}

			s := sqlscanner.New()
			result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
			if err != nil {
				t.Fatalf("ScanFull: %v", err)
			}

			// Build finding keys: "RULE:column"
			foundKeys := map[string]bool{}
			for _, f := range result.Findings {
				// Extract column name from description: "Sensitive column \"X\""
				col := extractColumnFromDesc(f.Description)
				key := f.RuleID + ":" + col
				foundKeys[key] = true
			}

			for key := range tt.wantRules {
				if !foundKeys[key] {
					t.Errorf("expected finding %s, not found; got findings: %v", key, foundKeys)
				}
			}
			for key := range tt.wantAbsent {
				if foundKeys[key] {
					t.Errorf("expected finding %s to be suppressed, but it was present", key)
				}
			}
		})
	}
}

// extractColumnFromDesc extracts column name from description like
// `Sensitive column "number" declared in SQL schema.`
func extractColumnFromDesc(desc string) string {
	i := strings.Index(desc, `"`)
	if i < 0 {
		return ""
	}
	j := strings.Index(desc[i+1:], `"`)
	if j < 0 {
		return ""
	}
	return desc[i+1 : i+1+j]
}

// copyFixtureAs copies a source file into tmpDir with a custom destination name.
func copyFixtureAs(t *testing.T, tmpDir, srcPath, dstName string) {
	t.Helper()
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read %s: %v", srcPath, err)
	}
	dst := filepath.Join(tmpDir, dstName)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

// TestCrossRefSQLWithGoEncryption verifies: SQL findings are downgraded/suppressed
// when a matching Go struct has application-level encryption for the column.
func TestCrossRefSQLWithGoEncryption(t *testing.T) {
	t.Parallel()
	sqlFixture := filepath.Join("testdata", "migrations", "encrypt_crossref.sql")
	goFixture := filepath.Join("testdata", "models", "card_encrypt_crossref.go")
	for _, f := range []string{sqlFixture, goFixture} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("fixture missing: %v", err)
		}
	}

	// Scan directory with BOTH SQL and Go fixtures → cross-reference triggers.
	tmp := t.TempDir()
	copyFixtureAs(t, tmp, sqlFixture, "encrypt_crossref.sql")
	copyFixtureAs(t, tmp, goFixture, "card_encrypt_crossref.go")

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull: %v", err)
	}

	// Build finding keys for SQL findings only.
	type findingInfo struct {
		ruleID   string
		col      string
		severity scanner.Severity
	}
	var sqlFindings []findingInfo
	for _, f := range result.Findings {
		if !strings.HasSuffix(f.FilePath, ".sql") {
			continue
		}
		col := extractColumnFromDesc(f.Description)
		sqlFindings = append(sqlFindings, findingInfo{f.RuleID, col, f.Severity})
	}

	// number text → SQL-SENSITIVE-COLUMN should be downgraded to INFO.
	numberFound := false
	for _, f := range sqlFindings {
		if f.ruleID == sqlscanner.RuleSQLSensitiveColumn && f.col == "number" {
			numberFound = true
			if f.severity != scanner.SeverityInfo {
				t.Errorf("cross-ref: number should be INFO, got %s", f.severity)
			}
		}
	}
	if !numberFound {
		t.Error("expected SQL-SENSITIVE-COLUMN for number (downgraded to INFO)")
	}

	// exp_month/exp_year → should be suppressed entirely.
	for _, f := range sqlFindings {
		if f.ruleID == sqlscanner.RuleSQLSensitiveColumn && (f.col == "exp_month" || f.col == "exp_year") {
			t.Errorf("cross-ref: %s should be suppressed, but found with severity %s", f.col, f.severity)
		}
	}
}

// TestCrossRefNoGoMatch verifies that SQL findings keep original severity
// when no matching Go struct is found in the project.
func TestCrossRefNoGoMatch(t *testing.T) {
	t.Parallel()
	sqlFixture := filepath.Join("testdata", "migrations", "encrypt_crossref.sql")
	if _, err := os.Stat(sqlFixture); err != nil {
		t.Skipf("fixture missing: %v", err)
	}

	// Scan directory with SQL fixture ONLY → no Go structs → no cross-ref.
	tmp := copyFixtures(t, sqlFixture)

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull: %v", err)
	}

	for _, f := range result.Findings {
		if f.RuleID == sqlscanner.RuleSQLSensitiveColumn {
			col := extractColumnFromDesc(f.Description)
			if f.Severity != scanner.SeverityHigh {
				t.Errorf("without Go match: %s should stay HIGH, got %s", col, f.Severity)
			}
		}
	}
}

func TestScanFullMigrationDropDowngradeIntegration(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	migDir := filepath.Join(tmp, "migrations")
	if err := os.MkdirAll(migDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	addPath := filepath.Join(migDir, "20240101000000_a.sql")
	dropPath := filepath.Join(migDir, "20260101000000_b.sql")
	addSQL := "CREATE TABLE legacy_card (\n    id BIGSERIAL PRIMARY KEY,\n    pan TEXT NOT NULL\n);\n"
	dropSQL := "ALTER TABLE legacy_card DROP COLUMN IF EXISTS pan;\n"
	if err := os.WriteFile(addPath, []byte(addSQL), 0o644); err != nil {
		t.Fatalf("write add: %v", err)
	}
	if err := os.WriteFile(dropPath, []byte(dropSQL), 0o644); err != nil {
		t.Fatalf("write drop: %v", err)
	}

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull: %v", err)
	}

	var panFindings []scanner.Finding
	for _, f := range result.Findings {
		if strings.HasSuffix(filepath.ToSlash(f.FilePath), "20240101000000_a.sql") {
			panFindings = append(panFindings, f)
		}
	}
	if len(panFindings) == 0 {
		t.Fatalf("no findings on add file, got %d total", len(result.Findings))
	}
	for _, f := range panFindings {
		if f.Severity != scanner.SeverityInfo {
			t.Errorf("finding %s severity = %s, want INFO", f.RuleID, f.Severity)
		}
		if !strings.HasPrefix(f.TriageHint, "downgrade:column_dropped_in_20260101000000_b") {
			t.Errorf("TriageHint = %q, want prefix downgrade:column_dropped_in_20260101000000_b", f.TriageHint)
		}
	}
}

// Regression for the cross-ref + migration-drop alignment bug:
// crossRefSQLWithGoEncryption suppresses an expiry column (deletes the
// finding) when the table has Go-level PAN encryption. Before the fix,
// sqlMetas / sqlFindingEnd were not pruned in lockstep, so the subsequent
// applyMigrationDropDowngrade pass paired SQL findings with the wrong
// meta. In this scenario the CVV SQL-SENSITIVE-COLUMN finding (dropped in
// a later migration) was left at HIGH instead of being downgraded to INFO.
func TestScanFullMigrationDropAfterCrossRefSuppression(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	migDir := filepath.Join(tmp, "migrations")
	if err := os.MkdirAll(migDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	addPath := filepath.Join(migDir, "20240101000000_init.sql")
	dropPath := filepath.Join(migDir, "20260101000000_drop_cvv.sql")
	addSQL := "CREATE TABLE legacy_card (\n    id BIGSERIAL PRIMARY KEY,\n    number TEXT NOT NULL,\n    exp_month BIGINT,\n    cvv TEXT\n);\n"
	dropSQL := "ALTER TABLE legacy_card DROP COLUMN cvv;\n"
	if err := os.WriteFile(addPath, []byte(addSQL), 0o644); err != nil {
		t.Fatalf("write add: %v", err)
	}
	if err := os.WriteFile(dropPath, []byte(dropSQL), 0o644); err != nil {
		t.Fatalf("write drop: %v", err)
	}

	goSrc := `package model

type LegacyCard struct {
	ID     int64  ` + "`gorm:\"primaryKey\"`" + `
	Number string ` + "`gorm:\"column:number\"`" + `
}

func (l *LegacyCard) TableName() string { return "legacy_card" }

func (l *LegacyCard) BeforeCreate() error {
	l.Number = Encrypt(l.Number)
	return nil
}

func Encrypt(s string) string { return s }
`
	if err := os.WriteFile(filepath.Join(tmp, "model.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatalf("write go: %v", err)
	}

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull: %v", err)
	}

	var cvvSensitive *scanner.Finding
	for i := range result.Findings {
		f := &result.Findings[i]
		if !strings.HasSuffix(filepath.ToSlash(f.FilePath), "20240101000000_init.sql") {
			continue
		}
		if f.RuleID != sqlscanner.RuleSQLSensitiveColumn {
			continue
		}
		if !strings.Contains(f.Description, `"cvv"`) {
			continue
		}
		cvvSensitive = f
		break
	}
	if cvvSensitive == nil {
		t.Fatalf("expected SQL-SENSITIVE-COLUMN for cvv on add migration, got %d findings total", len(result.Findings))
	}
	if cvvSensitive.Severity != scanner.SeverityInfo {
		t.Errorf("cvv SQL-SENSITIVE-COLUMN severity = %s, want INFO (column dropped in later migration)", cvvSensitive.Severity)
	}
	if !strings.HasPrefix(cvvSensitive.TriageHint, "downgrade:column_dropped_in_20260101000000_drop_cvv") {
		t.Errorf("cvv TriageHint = %q, want prefix downgrade:column_dropped_in_20260101000000_drop_cvv", cvvSensitive.TriageHint)
	}

	for _, f := range result.Findings {
		if f.RuleID != sqlscanner.RuleSQLSensitiveColumn {
			continue
		}
		if !strings.Contains(f.Description, `"exp_month"`) {
			continue
		}
		t.Errorf("exp_month SQL-SENSITIVE-COLUMN should have been suppressed by crossRefSQLWithGoEncryption (Go encrypts PAN), got severity=%s", f.Severity)
	}
}

// gorm:"...;serializer:json" is a marshaling directive, not encryption-at-rest;
// suppressing GORM-NO-ENCRYPT-HOOK on it would silently mask unencrypted CHD.
func TestScanFullSerializerJSONDoesNotSuppressEncryptHookFinding(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()

	goSrc := `package model

type SerializedCard struct {
	ID  int64  ` + "`gorm:\"primaryKey\"`" + `
	CVV string ` + "`gorm:\"column:cvv;serializer:json\"`" + `
}
`
	if err := os.WriteFile(filepath.Join(tmp, "model.go"), []byte(goSrc), 0o644); err != nil {
		t.Fatalf("write go: %v", err)
	}

	s := sqlscanner.New()
	result, err := s.ScanFull(context.Background(), tmp, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull: %v", err)
	}

	var noHook *scanner.Finding
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.RuleID == sqlscanner.RuleGormEncryptOK {
			t.Errorf("unexpected GORM-ENCRYPT-OK on serializer:json field: %+v", f)
		}
		if f.RuleID == sqlscanner.RuleGormNoEncryptHook {
			noHook = f
		}
	}
	if noHook == nil {
		t.Fatalf("expected GORM-NO-ENCRYPT-HOOK on serializer:json field, got %d findings total", len(result.Findings))
	}
	if noHook.Severity != scanner.SeverityHigh {
		t.Errorf("GORM-NO-ENCRYPT-HOOK severity = %q, want HIGH (serializer:json must not downgrade)", noHook.Severity)
	}
	if noHook.RequirementID != "3.5.1" {
		t.Errorf("GORM-NO-ENCRYPT-HOOK req = %q, want 3.5.1", noHook.RequirementID)
	}
}
