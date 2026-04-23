package sqlscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseSQLFile exercises the CREATE TABLE / ALTER TABLE ADD COLUMN extraction
// against positive.sql and negative.sql fixtures plus inline cases. It covers
// six behavior cases for SQL schema parsing.
func TestParseSQLFile(t *testing.T) {
	t.Parallel()
	type expected struct {
		name      string
		sqlType   string
		minLine   int // lower bound for the reported line (>0)
		sensitive bool
		plaintext bool
	}

	tests := []struct {
		name string
		src  string
		want []expected
	}{
		{
			name: "case1_create_table_card_number_text_and_expiry_date",
			src:  `CREATE TABLE cards (id serial, card_number text NOT NULL, expiry date);`,
			want: []expected{
				{name: "id", sqlType: "serial", minLine: 1, sensitive: false, plaintext: false},
				{name: "card_number", sqlType: "text", minLine: 1, sensitive: true, plaintext: true},
				{name: "expiry", sqlType: "date", minLine: 1, sensitive: true, plaintext: false},
			},
		},
		{
			name: "case2_create_table_tokens_non_sensitive",
			src:  `CREATE TABLE tokens (id serial, token_hash bytea NOT NULL);`,
			want: []expected{
				{name: "id", sqlType: "serial", minLine: 1, sensitive: false, plaintext: false},
				{name: "token_hash", sqlType: "bytea", minLine: 1, sensitive: false, plaintext: false},
			},
		},
		{
			name: "case3_alter_table_add_column_cvv_varchar",
			src:  `ALTER TABLE users ADD COLUMN cvv varchar(4) NOT NULL;`,
			want: []expected{
				{name: "cvv", sqlType: "varchar(4)", minLine: 1, sensitive: true, plaintext: true},
			},
		},
		{
			name: "case4_create_table_pan_bytea",
			src:  `CREATE TABLE x (pan bytea);`,
			want: []expected{
				{name: "pan", sqlType: "bytea", minLine: 1, sensitive: true, plaintext: false},
			},
		},
		{
			name: "case5_multi_statement_with_comments",
			src:  "-- +goose Up\nCREATE TABLE cards (id serial, card_number text);\n-- +goose Down\nDROP TABLE cards;\n",
			want: []expected{
				{name: "id", sqlType: "serial", minLine: 2, sensitive: false, plaintext: false},
				{name: "card_number", sqlType: "text", minLine: 2, sensitive: true, plaintext: true},
			},
		},
		{
			name: "case6_line_tracking_multiline_create_table",
			src:  "CREATE TABLE cards (\n    id serial PRIMARY KEY,\n    card_number text NOT NULL,\n    expiry date\n);\n",
			want: []expected{
				{name: "id", sqlType: "serial", minLine: 2, sensitive: false, plaintext: false},
				{name: "card_number", sqlType: "text", minLine: 3, sensitive: true, plaintext: true},
				{name: "expiry", sqlType: "date", minLine: 4, sensitive: true, plaintext: false},
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSQLFile(tc.src)
			if len(got) != len(tc.want) {
				t.Fatalf("ParseSQLFile returned %d columns, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				g := got[i]
				if g.Name != w.name {
					t.Errorf("col[%d] Name = %q, want %q", i, g.Name, w.name)
				}
				if g.SQLType != w.sqlType {
					t.Errorf("col[%d] SQLType = %q, want %q", i, g.SQLType, w.sqlType)
				}
				if g.Line < w.minLine {
					t.Errorf("col[%d] Line = %d, want >= %d", i, g.Line, w.minLine)
				}
				if got, want := isSensitiveColumn(g.Name), w.sensitive; got != want {
					t.Errorf("col[%d] isSensitiveColumn(%q) = %v, want %v", i, g.Name, got, want)
				}
				if got, want := IsPlaintextStringType(g.SQLType), w.plaintext; got != want {
					t.Errorf("col[%d] IsPlaintextStringType(%q) = %v, want %v", i, g.SQLType, got, want)
				}
			}
		})
	}
}

// TestParseSQLFile_FixturePositive parses the positive fixture end-to-end.
func TestParseSQLFile_FixturePositive(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "migrations", "positive.sql"))
	if err != nil {
		t.Fatalf("read positive fixture: %v", err)
	}
	cols := ParseSQLFile(string(data))
	if len(cols) == 0 {
		t.Fatalf("expected non-zero columns in positive fixture")
	}

	// Must contain at least: card_number text, expiry date, cvv varchar(4), pan bytea.
	requiredNames := []string{"card_number", "expiry", "cvv", "pan"}
	found := make(map[string]bool)
	for _, c := range cols {
		found[c.Name] = true
		if c.Line <= 0 {
			t.Errorf("column %q has non-positive line %d", c.Name, c.Line)
		}
	}
	for _, n := range requiredNames {
		if !found[n] {
			t.Errorf("positive fixture missing expected column %q", n)
		}
	}

	// DROP TABLE statements must NOT produce columns (only CREATE TABLE / ALTER).
	// If DROP were parsed we'd get phantom columns whose name is "cards" or "vaults".
	for _, c := range cols {
		if strings.EqualFold(c.Name, "cards") || strings.EqualFold(c.Name, "vaults") {
			t.Errorf("DROP TABLE should be ignored, but got column %q", c.Name)
		}
	}
}

// TestParseSQLFile_FixtureNegative confirms the negative fixture yields no
// SENSITIVE columns (non-sensitive columns may still be extracted — that's fine).
func TestParseSQLFile_FixtureNegative(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "migrations", "negative.sql"))
	if err != nil {
		t.Fatalf("read negative fixture: %v", err)
	}
	cols := ParseSQLFile(string(data))
	for _, c := range cols {
		if isSensitiveColumn(c.Name) {
			t.Errorf("negative fixture should have no sensitive columns, got %q", c.Name)
		}
	}
}

// TestParseSQLFile_TableName verifies that Column.TableName is populated
// from CREATE TABLE and ALTER TABLE statements.
func TestParseSQLFile_TableName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		src      string
		wantCols []struct {
			name      string
			tableName string
		}
	}{
		{
			name: "create_table_cards",
			src:  "CREATE TABLE \"cards\" (\n    id uuid PRIMARY KEY,\n    number text NULL\n);\n",
			wantCols: []struct {
				name      string
				tableName string
			}{
				{name: "id", tableName: "cards"},
				{name: "number", tableName: "cards"},
			},
		},
		{
			name: "create_table_if_not_exists",
			src:  "CREATE TABLE IF NOT EXISTS users (id serial, email text);\n",
			wantCols: []struct {
				name      string
				tableName string
			}{
				{name: "id", tableName: "users"},
				{name: "email", tableName: "users"},
			},
		},
		{
			name: "alter_table_add_column",
			src:  "ALTER TABLE \"cards\" ADD COLUMN verification_code text;\n",
			wantCols: []struct {
				name      string
				tableName string
			}{
				{name: "verification_code", tableName: "cards"},
			},
		},
		{
			name: "mixed_create_and_alter",
			src: `CREATE TABLE "cards" (id uuid, number text);
ALTER TABLE "users" ADD COLUMN account varchar(100);`,
			wantCols: []struct {
				name      string
				tableName string
			}{
				{name: "id", tableName: "cards"},
				{name: "number", tableName: "cards"},
				{name: "account", tableName: "users"},
			},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cols := ParseSQLFile(tc.src)
			if len(cols) != len(tc.wantCols) {
				t.Fatalf("got %d columns, want %d: %+v", len(cols), len(tc.wantCols), cols)
			}
			for i, w := range tc.wantCols {
				g := cols[i]
				if g.Name != w.name {
					t.Errorf("col[%d] Name = %q, want %q", i, g.Name, w.name)
				}
				if g.TableName != w.tableName {
					t.Errorf("col[%d] TableName = %q, want %q", i, g.TableName, w.tableName)
				}
			}
		})
	}
}

// TestParseSQLFile_FixtureContextAware parses the context_aware.sql fixture and
// verifies that columns from the "cards" table have TableName="cards" and columns
// from the "users" table have TableName="users".
func TestParseSQLFile_FixtureContextAware(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("testdata", "migrations", "context_aware.sql"))
	if err != nil {
		t.Fatalf("read context_aware fixture: %v", err)
	}
	cols := ParseSQLFile(string(data))
	if len(cols) == 0 {
		t.Fatal("expected non-zero columns in context_aware fixture")
	}

	// Verify table names.
	cardsCols := 0
	usersCols := 0
	for _, c := range cols {
		switch c.TableName {
		case "cards":
			cardsCols++
		case "users":
			usersCols++
		default:
			t.Errorf("unexpected TableName %q for column %q", c.TableName, c.Name)
		}
	}
	if cardsCols == 0 {
		t.Error("expected at least one column with TableName=cards")
	}
	if usersCols == 0 {
		t.Error("expected at least one column with TableName=users")
	}

	// Verify ALTER TABLE column also has TableName.
	found := false
	for _, c := range cols {
		if c.Name == "verification_code" {
			found = true
			if c.TableName != "cards" {
				t.Errorf("verification_code TableName = %q, want cards", c.TableName)
			}
		}
	}
	if !found {
		t.Error("ALTER TABLE column verification_code not found")
	}
}

// TestIsPlaintextStringType covers the regex matrix for plaintext SQL string types.
func TestIsPlaintextStringType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		typ  string
		want bool
	}{
		{"text", true},
		{"TEXT", true},
		{"varchar", true},
		{"varchar(255)", true},
		{"character varying", true},
		{"character varying(128)", true},
		{"char", true},
		{"char(16)", true},
		{"citext", true},
		{"string", true},
		{"bytea", false},
		{"date", false},
		{"serial", false},
		{"integer", false},
		{"numeric(10,2)", false},
		{"timestamp", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := IsPlaintextStringType(tc.typ); got != tc.want {
			t.Errorf("IsPlaintextStringType(%q) = %v, want %v", tc.typ, got, tc.want)
		}
	}
}
