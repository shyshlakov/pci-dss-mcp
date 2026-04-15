package sqlscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestExtractDBTag covers gorm/db/sql tag parsing.
func TestExtractDBTag(t *testing.T) {
	tests := []struct {
		name       string
		tag        string
		wantColumn string
		wantSource string
	}{
		{
			name:       "gorm column prefix",
			tag:        "`gorm:\"column:card_number\"`",
			wantColumn: "card_number",
			wantSource: "gorm",
		},
		{
			name:       "gorm with extras",
			tag:        "`gorm:\"column:cvv;not null;size:4\"`",
			wantColumn: "cvv",
			wantSource: "gorm",
		},
		{
			name:       "db tag",
			tag:        "`db:\"pan\"`",
			wantColumn: "pan",
			wantSource: "db",
		},
		{
			name:       "sql tag",
			tag:        "`sql:\"cvv\"`",
			wantColumn: "cvv",
			wantSource: "sql",
		},
		{
			name:       "no tag",
			tag:        "",
			wantColumn: "",
			wantSource: "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotCol, gotSrc := extractDBTag(tc.tag)
			if gotCol != tc.wantColumn || gotSrc != tc.wantSource {
				t.Errorf("extractDBTag(%q) = (%q,%q), want (%q,%q)",
					tc.tag, gotCol, gotSrc, tc.wantColumn, tc.wantSource)
			}
		})
	}
}

// TestParseGormStructs covers the six behavior cases for GORM struct parsing.
func TestParseGormStructs(t *testing.T) {
	tests := []struct {
		name               string
		src                string
		wantStructCount    int
		wantStructName     string
		wantSensitive      []string // expected sensitive column names (in order)
		wantHasEncryptHook bool
	}{
		{
			name: "case1_gorm_tag_no_hook",
			src: `package p
type Card struct {
	Number string ` + "`gorm:\"column:card_number\"`" + `
}
`,
			wantStructCount:    1,
			wantStructName:     "Card",
			wantSensitive:      []string{"card_number"},
			wantHasEncryptHook: false,
		},
		{
			name: "case2_gorm_tag_with_before_create_encrypt",
			src: `package p
import "fmt"
type Card struct {
	CVV string ` + "`gorm:\"column:cvv\"`" + `
}
func Encrypt(s string) string { return s }
func (c *Card) BeforeCreate(tx interface{}) error {
	c.CVV = Encrypt(c.CVV)
	fmt.Println("hook")
	return nil
}
`,
			wantStructCount:    1,
			wantStructName:     "Card",
			wantSensitive:      []string{"cvv"},
			wantHasEncryptHook: true,
		},
		{
			name: "case3_db_tag_pan",
			src: `package p
type Account struct {
	PAN string ` + "`db:\"pan\"`" + `
}
`,
			wantStructCount:    1,
			wantStructName:     "Account",
			wantSensitive:      []string{"pan"},
			wantHasEncryptHook: false,
		},
		{
			name: "case4_before_create_without_encrypt_call",
			src: `package p
type Card struct {
	CVV string ` + "`gorm:\"column:cvv\"`" + `
}
func (c *Card) BeforeCreate(tx interface{}) error {
	return nil
}
`,
			wantStructCount:    1,
			wantStructName:     "Card",
			wantSensitive:      []string{"cvv"},
			wantHasEncryptHook: false,
		},
		{
			name: "case5_value_receiver_hook_still_counts",
			src: `package p
type Card struct {
	CVV string ` + "`gorm:\"column:cvv\"`" + `
}
func Encrypt(s string) string { return s }
func (c Card) BeforeCreate(tx interface{}) error {
	_ = Encrypt(c.CVV)
	return nil
}
`,
			wantStructCount:    1,
			wantStructName:     "Card",
			wantSensitive:      []string{"cvv"},
			wantHasEncryptHook: true,
		},
		{
			name: "case6_non_sensitive_gorm_tag",
			src: `package p
type User struct {
	Email string ` + "`gorm:\"column:email\"`" + `
}
`,
			wantStructCount: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			structs := ParseGormStructs(f, fset)
			if len(structs) != tc.wantStructCount {
				t.Fatalf("got %d structs, want %d: %+v", len(structs), tc.wantStructCount, structs)
			}
			if tc.wantStructCount == 0 {
				return
			}
			gs := structs[0]
			if gs.Name != tc.wantStructName {
				t.Errorf("Name = %q, want %q", gs.Name, tc.wantStructName)
			}
			if gs.HasEncryptHook != tc.wantHasEncryptHook {
				t.Errorf("HasEncryptHook = %v, want %v", gs.HasEncryptHook, tc.wantHasEncryptHook)
			}
			if len(gs.SensitiveTags) != len(tc.wantSensitive) {
				t.Fatalf("SensitiveTags count = %d, want %d: %+v",
					len(gs.SensitiveTags), len(tc.wantSensitive), gs.SensitiveTags)
			}
			for i, want := range tc.wantSensitive {
				if gs.SensitiveTags[i].ColumnName != want {
					t.Errorf("SensitiveTags[%d].ColumnName = %q, want %q",
						i, gs.SensitiveTags[i].ColumnName, want)
				}
				if gs.SensitiveTags[i].Line <= 0 {
					t.Errorf("SensitiveTags[%d].Line = %d, want > 0", i, gs.SensitiveTags[i].Line)
				}
			}
		})
	}
}

// TestHookEncryptedFields verifies field-level encryption detection.
func TestHookEncryptedFields(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want map[string]bool
	}{
		{
			name: "single_field_encrypt",
			src: `package p
type Card struct { Number string }
func Encrypt(s string) (string, error) { return s, nil }
func (c *Card) BeforeCreate(tx interface{}) error {
	c.Number, _ = Encrypt(c.Number)
	return nil
}
`,
			want: map[string]bool{"Number": true},
		},
		{
			name: "multiple_fields_encrypt",
			src: `package p
type Card struct { CVV string; Number string }
func Encrypt(s string) string { return s }
func (c *Card) BeforeCreate(tx interface{}) error {
	c.CVV = Encrypt(c.CVV)
	c.Number = Encrypt(c.Number)
	return nil
}
`,
			want: map[string]bool{"CVV": true, "Number": true},
		},
		{
			name: "no_encrypt_calls",
			src: `package p
type Card struct { Number string }
func (c *Card) BeforeCreate(tx interface{}) error {
	return nil
}
`,
			want: map[string]bool{},
		},
		{
			name: "decrypt_in_after_find",
			src: `package p
type Card struct { Number string }
func Decrypt(s string) (string, error) { return s, nil }
func (c *Card) AfterFind(tx interface{}) error {
	c.Number, _ = Decrypt(c.Number)
	return nil
}
`,
			want: map[string]bool{"Number": true},
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			// Find the hook function body to test hookEncryptedFields.
			got := map[string]bool{}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv == nil || fn.Body == nil {
					continue
				}
				fields := hookEncryptedFields(fn.Body)
				for k, v := range fields {
					got[k] = v
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("hookEncryptedFields returned %v, want %v", got, tc.want)
			}
			for k := range tc.want {
				if !got[k] {
					t.Errorf("expected field %q in encrypted set, not found", k)
				}
			}
		})
	}
}

// TestResolveStructTableName verifies table name resolution.
func TestResolveStructTableName(t *testing.T) {
	tests := []struct {
		name       string
		src        string
		structName string
		want       string
	}{
		{
			name: "tablename_method_literal",
			src: `package p
type Card struct {}
func (c *Card) TableName() string { return "cards" }
`,
			structName: "Card",
			want:       "cards",
		},
		{
			name: "tablename_method_constant",
			src: `package p
const CardTableName = "cards"
type Card struct {}
func (c *Card) TableName() string { return CardTableName }
`,
			structName: "Card",
			want:       "cards",
		},
		{
			name: "heuristic_card_struct",
			src: `package p
type Card struct {}
`,
			structName: "Card",
			want:       "cards",
		},
		{
			name: "heuristic_payment_struct",
			src: `package p
type PaymentMethod struct {}
`,
			structName: "PaymentMethod",
			want:       "paymentmethods",
		},
		{
			name: "no_match",
			src: `package p
type User struct {}
`,
			structName: "User",
			want:       "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := resolveStructTableName(f, tc.structName)
			if got != tc.want {
				t.Errorf("resolveStructTableName(%q) = %q, want %q", tc.structName, got, tc.want)
			}
		})
	}
}

// TestParseGormStructsWithContext verifies context-aware struct parsing.
func TestParseGormStructsWithContext(t *testing.T) {
	tests := []struct {
		name            string
		src             string
		wantStructCount int
		wantStructName  string
		wantSensitive   []string
		wantEncrypted   map[string]bool
		wantTableName   string
	}{
		{
			name: "card_encrypted_number_only",
			src: `package p
const CardTableName = "cards"
type Card struct {
	ID       string ` + "`gorm:\"column:id;primaryKey\"`" + `
	Number   string ` + "`gorm:\"column:number\"`" + `
	ExpMonth int64  ` + "`gorm:\"column:exp_month\"`" + `
	ExpYear  int64  ` + "`gorm:\"column:exp_year\"`" + `
}
func (c *Card) TableName() string { return CardTableName }
func Encrypt(s string) (string, error) { return s, nil }
func Decrypt(s string) (string, error) { return s, nil }
func (c *Card) BeforeCreate(tx interface{}) error {
	c.Number, _ = Encrypt(c.Number)
	return nil
}
func (c *Card) AfterFind(tx interface{}) error {
	c.Number, _ = Decrypt(c.Number)
	return nil
}
`,
			wantStructCount: 1,
			wantStructName:  "Card",
			wantSensitive:   []string{"number"}, // only number, not exp_month/year (panProtected)
			wantEncrypted:   map[string]bool{"Number": true},
			wantTableName:   "cards",
		},
		{
			name: "bad_card_no_encrypt",
			src: `package p
type BadCard struct {
	ID       string ` + "`gorm:\"column:id;primaryKey\"`" + `
	Number   string ` + "`gorm:\"column:number\"`" + `
	ExpMonth int64  ` + "`gorm:\"column:exp_month\"`" + `
	ExpYear  int64  ` + "`gorm:\"column:exp_year\"`" + `
}
func (c *BadCard) TableName() string { return "cards" }
`,
			wantStructCount: 1,
			wantStructName:  "BadCard",
			wantSensitive:   []string{"number", "exp_month", "exp_year"},
			wantEncrypted:   map[string]bool{},
			wantTableName:   "cards",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			structs := ParseGormStructsWithContext(f, fset)
			if len(structs) != tc.wantStructCount {
				t.Fatalf("got %d structs, want %d: %+v", len(structs), tc.wantStructCount, structs)
			}
			if tc.wantStructCount == 0 {
				return
			}
			gs := structs[0]
			if gs.Name != tc.wantStructName {
				t.Errorf("Name = %q, want %q", gs.Name, tc.wantStructName)
			}
			if gs.EffectiveTableName != tc.wantTableName {
				t.Errorf("EffectiveTableName = %q, want %q", gs.EffectiveTableName, tc.wantTableName)
			}
			var gotCols []string
			for _, tag := range gs.SensitiveTags {
				gotCols = append(gotCols, tag.ColumnName)
			}
			if len(gotCols) != len(tc.wantSensitive) {
				t.Fatalf("SensitiveTags columns = %v, want %v", gotCols, tc.wantSensitive)
			}
			for i, want := range tc.wantSensitive {
				if gotCols[i] != want {
					t.Errorf("SensitiveTags[%d].ColumnName = %q, want %q", i, gotCols[i], want)
				}
			}
			for k := range tc.wantEncrypted {
				if !gs.EncryptedFields[k] {
					t.Errorf("expected %q in EncryptedFields", k)
				}
			}
		})
	}
}

// TestParseGormStructs_Fixtures exercises the shared testdata/models fixtures.
func TestParseGormStructs_Fixtures(t *testing.T) {
	cases := []struct {
		path               string
		wantStructName     string
		wantHasEncryptHook bool
	}{
		{
			path:               filepath.Join("testdata", "models", "with_hook.go"),
			wantStructName:     "Card",
			wantHasEncryptHook: true,
		},
		{
			path:               filepath.Join("testdata", "models", "without_hook.go"),
			wantStructName:     "Account",
			wantHasEncryptHook: false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, tc.path, nil, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", tc.path, err)
			}
			structs := ParseGormStructs(f, fset)
			if len(structs) == 0 {
				t.Fatalf("expected at least one struct in %s", tc.path)
			}
			found := false
			for _, s := range structs {
				if s.Name == tc.wantStructName {
					found = true
					if s.HasEncryptHook != tc.wantHasEncryptHook {
						t.Errorf("%s: HasEncryptHook = %v, want %v",
							tc.path, s.HasEncryptHook, tc.wantHasEncryptHook)
					}
					if len(s.SensitiveTags) == 0 {
						t.Errorf("%s: expected non-zero SensitiveTags", tc.path)
					}
				}
			}
			if !found {
				t.Errorf("%s: struct %q not found", tc.path, tc.wantStructName)
			}
		})
	}
}
