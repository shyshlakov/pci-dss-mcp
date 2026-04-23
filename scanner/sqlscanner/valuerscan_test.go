package sqlscanner

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestVerifyValueBody(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name           string
		typeName       string
		src            string
		wantVerified   bool
		wantHitContain string
	}{
		{
			name:     "direct_aes_gcm",
			typeName: "SecureString",
			src: `package p
import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"io"
)
var key = []byte("0123456789abcdef0123456789abcdef")
type SecureString string
func (s SecureString) Value() (driver.Value, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return gcm.Seal(nonce, nonce, []byte(s), nil), nil
}
func (s *SecureString) Scan(v interface{}) error { return nil }
`,
			wantVerified:   true,
			wantHitContain: "NewCipher",
		},
		{
			name:     "helper_recursion",
			typeName: "HelperEncryptedString",
			src: `package p
import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql/driver"
)
var key = []byte("0123456789abcdef0123456789abcdef")
func EncryptPAN(plaintext string) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, nil, []byte(plaintext), nil), nil
}
type HelperEncryptedString string
func (hes HelperEncryptedString) Value() (driver.Value, error) {
	return EncryptPAN(string(hes))
}
func (hes *HelperEncryptedString) Scan(v interface{}) error { return nil }
`,
			wantVerified:   true,
			wantHitContain: "NewCipher",
		},
		{
			name:     "fake_base64_only",
			typeName: "FakeEncryptedString",
			src: `package p
import (
	"database/sql/driver"
	"encoding/base64"
)
type FakeEncryptedString string
func (fes FakeEncryptedString) Value() (driver.Value, error) {
	return base64.StdEncoding.EncodeToString([]byte(fes)), nil
}
func (fes *FakeEncryptedString) Scan(v interface{}) error { return nil }
`,
			wantVerified:   false,
			wantHitContain: "",
		},
		{
			name:     "kms_vault_client",
			typeName: "KMSEncryptedString",
			src: `package p
import (
	"context"
	"database/sql/driver"
)
type VaultKMSClient struct{}
func (v *VaultKMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) { return plaintext, nil }
var vaultClient = &VaultKMSClient{}
type KMSEncryptedString string
func (kes KMSEncryptedString) Value() (driver.Value, error) {
	return vaultClient.Encrypt(context.Background(), []byte(kes))
}
func (kes *KMSEncryptedString) Scan(v interface{}) error { return nil }
`,
			wantVerified:   true,
			wantHitContain: "KMS:",
		},
		{
			name:     "import_only_no_call",
			typeName: "ImportOnly",
			src: `package p
import (
	_ "crypto/aes"
	"database/sql/driver"
	"encoding/hex"
)
type ImportOnly string
func (i ImportOnly) Value() (driver.Value, error) {
	return hex.EncodeToString([]byte(i)), nil
}
func (i *ImportOnly) Scan(v interface{}) error { return nil }
`,
			wantVerified:   false,
			wantHitContain: "",
		},
		{
			name:     "two_level_recursion",
			typeName: "DeepHelper",
			src: `package p
import (
	"crypto/aes"
	"database/sql/driver"
)
var key = []byte("0123456789abcdef0123456789abcdef")
func helperA(s string) ([]byte, error) {
	return helperB(s)
}
func helperB(s string) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	_ = block
	return []byte(s), nil
}
type DeepHelper string
func (d DeepHelper) Value() (driver.Value, error) {
	return helperA(string(d))
}
func (d *DeepHelper) Scan(v interface{}) error { return nil }
`,
			wantVerified:   false,
			wantHitContain: "",
		},
		{
			name:     "gorm_value_method",
			typeName: "GormValuerType",
			src: `package p
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
)
var key = []byte("0123456789abcdef0123456789abcdef")
type GormValuerType string
type fakeDB struct{}
type fakeExpr struct{}
func (g GormValuerType) GormValue(ctx context.Context, db *fakeDB) fakeExpr {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	_ = gcm
	return fakeExpr{}
}
`,
			wantVerified:   true,
			wantHitContain: "NewCipher",
		},
		{
			name:     "pointer_receiver",
			typeName: "PointerValuer",
			src: `package p
import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql/driver"
)
var key = []byte("0123456789abcdef0123456789abcdef")
type PointerValuer string
func (p *PointerValuer) Value() (driver.Value, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, nil, []byte(*p), nil), nil
}
func (p *PointerValuer) Scan(v interface{}) error { return nil }
`,
			wantVerified:   true,
			wantHitContain: "NewCipher",
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			vmap := buildVerifiedTypeMap(file, "test.go")
			vt, ok := vmap[tc.typeName]
			if !ok {
				t.Fatalf("type %q not in verified type map: keys=%v", tc.typeName, mapKeys(vmap))
			}
			pkgFuncs := collectPkgFuncs(file)

			gotVerified, gotHit := verifyValueBody(vt, pkgFuncs)
			if gotVerified != tc.wantVerified {
				t.Errorf("verifyValueBody(%s) verified=%v hit=%q, want verified=%v",
					tc.typeName, gotVerified, gotHit, tc.wantVerified)
			}
			if tc.wantHitContain != "" && !strings.Contains(gotHit, tc.wantHitContain) {
				t.Errorf("verifyValueBody(%s) hit=%q, want contains %q",
					tc.typeName, gotHit, tc.wantHitContain)
			}
		})
	}
}

func TestBuildVerifiedTypeMap(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name      string
		src       string
		wantTypes []string
	}{
		{
			name: "value_and_scan_both_present",
			src: `package p
import "database/sql/driver"
type T1 string
func (t T1) Value() (driver.Value, error) { return nil, nil }
func (t *T1) Scan(v interface{}) error { return nil }
`,
			wantTypes: []string{"T1"},
		},
		{
			name: "value_only_no_scan",
			src: `package p
import "database/sql/driver"
type T2 string
func (t T2) Value() (driver.Value, error) { return nil, nil }
`,
			wantTypes: []string{"T2"},
		},
		{
			name: "wrong_value_signature_excluded",
			src: `package p
type T3 string
func (t T3) Value(x int) (interface{}, error) { return nil, nil }
`,
			wantTypes: []string{},
		},
		{
			name: "gorm_value_only",
			src: `package p
import "context"
type fakeDB struct{}
type fakeExpr struct{}
type T4 string
func (t T4) GormValue(ctx context.Context, db *fakeDB) fakeExpr { return fakeExpr{} }
`,
			wantTypes: []string{"T4"},
		},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tc.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			vmap := buildVerifiedTypeMap(file, "test.go")

			gotKeys := mapKeys(vmap)
			if len(gotKeys) != len(tc.wantTypes) {
				t.Fatalf("got %d types %v, want %d %v", len(gotKeys), gotKeys, len(tc.wantTypes), tc.wantTypes)
			}
			for _, want := range tc.wantTypes {
				if _, ok := vmap[want]; !ok {
					t.Errorf("missing type %q in map (got %v)", want, gotKeys)
				}
			}
		})
	}
}

func mapKeys(m map[string]*valuerTypeInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBareTypeName(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain", "EncryptedString", "EncryptedString"},
		{"pointer", "*EncryptedString", "EncryptedString"},
		{"slice", "[]EncryptedString", "EncryptedString"},
		{"slice_of_pointer", "[]*EncryptedString", "EncryptedString"},
		{"pointer_to_slice", "*[]EncryptedString", "EncryptedString"},
		{"qualified", "crypto.EncryptedString", "EncryptedString"},
		{"slice_qualified", "[]crypto.EncryptedString", "EncryptedString"},
		{"pointer_qualified", "*crypto.EncryptedString", "EncryptedString"},
		{"slice_of_pointer_qualified", "[]*crypto.EncryptedString", "EncryptedString"},
		{"with_whitespace", "  *EncryptedString  ", "EncryptedString"},
		{"empty", "", ""},
	}

	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := bareTypeName(tc.input)
			if got != tc.expected {
				t.Errorf("bareTypeName(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestApplyVerifiedTypeFixupSliceField(t *testing.T) {
	t.Parallel()
	src := `package p
import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql/driver"
)
var key = []byte("0123456789abcdef0123456789abcdef")
type EncryptedPAN string
func (e EncryptedPAN) Value() (driver.Value, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	return gcm.Seal(nil, nil, []byte(e), nil), nil
}
func (e *EncryptedPAN) Scan(v interface{}) error { return nil }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	vmap := buildVerifiedTypeMap(file, "test.go")
	if _, ok := vmap["EncryptedPAN"]; !ok {
		t.Fatalf("EncryptedPAN missing from verified type map: keys=%v", mapKeys(vmap))
	}
	pkgFuncs := collectPkgFuncEntries(file)

	gs := &GormStruct{
		Name:           "CardModel",
		Line:           42,
		HasEncryptHook: false,
		SensitiveTags: []SensitiveTag{
			{
				FieldName:  "Pans",
				ColumnName: "pans",
				TagSource:  "gorm",
				FieldType:  "[]EncryptedPAN",
				Line:       43,
			},
		},
	}
	structByLocation := map[string]*GormStruct{
		structKey("test.go", 42): gs,
	}
	findings := []scanner.Finding{
		{
			RuleID:        RuleGormNoEncryptHook,
			Severity:      scanner.SeverityHigh,
			RequirementID: "3.5.1",
			FilePath:      "test.go",
			Line:          42,
			Description:   "Struct CardModel stores sensitive cardholder columns but has no hook.",
		},
	}

	out := applyVerifiedTypeFixup(findings, structByLocation, vmap, pkgFuncs)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].RuleID != RuleGormEncryptOK {
		t.Errorf("slice-of-encrypted-type: RuleID = %q, want %q", out[0].RuleID, RuleGormEncryptOK)
	}
	if out[0].Severity != scanner.SeverityInfo {
		t.Errorf("slice-of-encrypted-type: Severity = %q, want INFO", out[0].Severity)
	}
}
