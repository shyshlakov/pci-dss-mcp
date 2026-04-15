package retentionscanner

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Redis Tests (R1-R8) ---

func TestDetectRedisWithoutTTL(t *testing.T) {
	tests := []struct {
		name          string
		src           string
		wantFindings  int
		wantRuleIDs   []string
		wantSeverity  string
		dontWantRules []string
	}{
		{
			name: "R1: Set with TTL=0 on sensitive var",
			src: `package test
import "time"
type R struct{}
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	cardData := "4111"
	rdb.Set(nil, "card_data", cardData, 0)
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-REDIS-NO-TTL"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "R2: Set with time.Duration(0) on sensitive var",
			src: `package test
import "time"
type R struct{}
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	cardData := "4111"
	rdb.Set(nil, "card_data", cardData, time.Duration(0))
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-REDIS-NO-TTL"},
		},
		{
			name: "R3: Set with positive TTL on sensitive var - no finding",
			src: `package test
import "time"
type R struct{}
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	cardData := "4111"
	rdb.Set(nil, "card_data", cardData, 5*time.Minute)
}`,
			wantFindings: 0,
		},
		{
			name: "R4: SetNX with TTL=0 on sensitive var",
			src: `package test
import "time"
type R struct{}
func (r *R) SetNX(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	panCache := "4111"
	rdb.SetNX(nil, "pan_cache", panCache, 0)
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-REDIS-NO-TTL"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "R5: HSet without Expire on sensitive data",
			src: `package test
type R struct{}
func (r *R) HSet(ctx interface{}, key string, values ...interface{}) {}
func example() {
	rdb := &R{}
	rdb.HSet(nil, "payment_hash", "pan", "4111111111111111")
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-REDIS-NO-EXPIRE"},
			wantSeverity: "HIGH",
		},
		{
			name: "R6: HSet with Expire nearby on sensitive data - no finding",
			src: `package test
import "time"
type R struct{}
func (r *R) HSet(ctx interface{}, key string, values ...interface{}) {}
func (r *R) Expire(ctx interface{}, key string, ttl time.Duration) {}
func example() {
	rdb := &R{}
	rdb.HSet(nil, "payment_hash", "pan", "4111111111111111")
	rdb.Expire(nil, "payment_hash", 1*time.Hour)
}`,
			wantFindings: 0,
		},
		{
			name: "R7: Set with KeepTTL on sensitive var",
			src: `package test
import "time"
type R struct{}
var KeepTTL time.Duration
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	cardData := "4111"
	rdb.Set(nil, "card_data", cardData, KeepTTL)
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-REDIS-KEEP-TTL"},
			wantSeverity: "HIGH",
		},
		{
			name: "R8: Set with TTL=0 on non-sensitive var - no finding",
			src: `package test
import "time"
type R struct{}
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	userName := "john"
	rdb.Set(nil, "user_name", userName, 0)
}`,
			wantFindings:  0,
			dontWantRules: []string{"RET-REDIS-NO-TTL"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}

			aliases := resolveImportAliases(file)
			findings := detectRedisWithoutTTL(file, fset, "test.go", aliases)

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for i, f := range findings {
					t.Logf("  finding[%d]: %s %s %s", i, f.RuleID, f.Severity, f.Description)
				}
			}

			for _, wantRule := range tt.wantRuleIDs {
				found := false
				for _, f := range findings {
					if f.RuleID == wantRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected RuleID %s not found in findings", wantRule)
				}
			}

			if tt.wantSeverity != "" && len(findings) > 0 {
				for _, f := range findings {
					if string(f.Severity) != tt.wantSeverity {
						t.Errorf("got severity %s, want %s", f.Severity, tt.wantSeverity)
					}
				}
			}

			for _, dontWant := range tt.dontWantRules {
				for _, f := range findings {
					if f.RuleID == dontWant {
						t.Errorf("unexpected RuleID %s found in findings", dontWant)
					}
				}
			}
		})
	}
}

// --- DB Tests (D1-D4) ---

func TestDetectDBStorageOfSensitiveData(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		wantFindings int
		wantRuleIDs  []string
		wantSeverity string
	}{
		{
			name: "D1: db.Exec INSERT with sensitive arg",
			src: `package test
type DB struct{}
func (d *DB) Exec(query string, args ...interface{}) {}
func example() {
	db := &DB{}
	cardNumber := "4111111111111111"
	db.Exec("INSERT INTO cards (number) VALUES (?)", cardNumber)
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-DB-SENSITIVE-STORE"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "D2: db.Create with sensitive struct",
			src: `package test
type DB struct{}
func (d *DB) Create(value interface{}) {}
type PaymentRecord struct { PAN string }
func example() {
	db := &DB{}
	pan := "4111"
	db.Create(&PaymentRecord{PAN: pan})
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-GORM-SENSITIVE-STORE"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "D3: db.Save with sensitive struct",
			src: `package test
type DB struct{}
func (d *DB) Save(value interface{}) {}
type PaymentRecord struct { CVV string }
func example() {
	db := &DB{}
	cvv := "123"
	db.Save(&PaymentRecord{CVV: cvv})
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-GORM-SENSITIVE-STORE"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "D4: db.Exec INSERT with non-sensitive data - no finding",
			src: `package test
type DB struct{}
func (d *DB) Exec(query string, args ...interface{}) {}
func example() {
	db := &DB{}
	name := "John"
	db.Exec("INSERT INTO users (name) VALUES (?)", name)
}`,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}

			aliases := resolveImportAliases(file)
			findings := detectDBStorageOfSensitiveData(file, fset, "test.go", aliases)

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for i, f := range findings {
					t.Logf("  finding[%d]: %s %s %s", i, f.RuleID, f.Severity, f.Description)
				}
			}

			for _, wantRule := range tt.wantRuleIDs {
				found := false
				for _, f := range findings {
					if f.RuleID == wantRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected RuleID %s not found in findings", wantRule)
				}
			}

			if tt.wantSeverity != "" && len(findings) > 0 {
				for _, f := range findings {
					if string(f.Severity) != tt.wantSeverity {
						t.Errorf("got severity %s, want %s", f.Severity, tt.wantSeverity)
					}
				}
			}
		})
	}
}

// --- Config Tests (C1-C4) ---

func TestDetectConfigMissingTTL(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		content      string
		wantFindings int
		wantRuleIDs  []string
		wantSeverity string
	}{
		{
			name:     "C1: YAML with card_data no TTL sibling",
			filename: "config.yaml",
			content: `card_processing:
  card_data:
    storage_key: "cards:active"
`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-CONFIG-NO-TTL"},
			wantSeverity: "HIGH",
		},
		{
			name:     "C2: YAML with card_data and TTL sibling - no finding",
			filename: "config.yaml",
			content: `card_processing:
  card_data:
    storage_key: "cards:active"
    ttl: 3600
`,
			wantFindings: 0,
		},
		{
			name:         "C3: JSON with payment_token no expiry sibling",
			filename:     "config.json",
			content:      `{"payment_token": {"enabled": true, "storage": "redis"}}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-CONFIG-NO-TTL"},
			wantSeverity: "HIGH",
		},
		{
			name:     "C4: TOML with cardholder_data section no TTL",
			filename: "config.toml",
			content: `[cardholder_data]
enabled = true
storage = "redis"
`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-CONFIG-NO-TTL"},
			wantSeverity: "HIGH",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, tt.filename)
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			findings, _, err := detectConfigMissingTTL(path)
			if err != nil {
				t.Fatalf("detectConfigMissingTTL: %v", err)
			}

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for i, f := range findings {
					t.Logf("  finding[%d]: %s %s %s", i, f.RuleID, f.Severity, f.Description)
				}
			}

			for _, wantRule := range tt.wantRuleIDs {
				found := false
				for _, f := range findings {
					if f.RuleID == wantRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected RuleID %s not found in findings", wantRule)
				}
			}

			if tt.wantSeverity != "" && len(findings) > 0 {
				for _, f := range findings {
					if string(f.Severity) != tt.wantSeverity {
						t.Errorf("got severity %s, want %s", f.Severity, tt.wantSeverity)
					}
				}
			}
		})
	}
}

// --- Zeroing Tests (Z1-Z4) ---

func TestDetectZeroingTimingIssues(t *testing.T) {
	tests := []struct {
		name         string
		src          string
		wantFindings int
		wantRuleIDs  []string
		wantSeverity string
	}{
		{
			name: "Z1: clear before authorize - CRITICAL",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func clearData(data []byte) {}
func ProcessPayment(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	clearData(cardData)
	authorize(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-BEFORE-AUTH"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "Z2: defer clear only - HIGH",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func clearData(data []byte) {}
func ProcessPayment(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	defer clearData(cardData)
	authorize(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-DEFER-ONLY"},
			wantSeverity: "HIGH",
		},
		{
			name: "Z3: clear after response write - HIGH",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func clearData(data []byte) {}
func ProcessPayment(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	authorize(cardData)
	w.Write([]byte("ok"))
	clearData(cardData)
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-AFTER-RESPONSE"},
			wantSeverity: "HIGH",
		},
		{
			name: "Z4: correct order authorize->clear->write - no finding",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func clearData(data []byte) {}
func ProcessPayment(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	authorize(cardData)
	clearData(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 0,
		},
		{
			name: "Z5: range-zero loop after response - HIGH",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func ProcessCardCharge(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	authorize(cardData)
	w.Write([]byte("ok"))
	for i := range cardData {
		cardData[i] = 0
	}
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-AFTER-RESPONSE"},
			wantSeverity: "HIGH",
		},
		{
			name: "Z6: range-zero loop before authorize - CRITICAL",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func ProcessCardCharge(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	for i := range cardData {
		cardData[i] = 0
	}
	authorize(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-BEFORE-AUTH"},
			wantSeverity: "CRITICAL",
		},
		{
			name: "Z7: defer IIFE range-zero - HIGH",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func ProcessCardCharge(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	defer func() {
		for i := range cardData {
			cardData[i] = 0
		}
	}()
	authorize(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 1,
			wantRuleIDs:  []string{"RET-ZERO-DEFER-ONLY"},
			wantSeverity: "HIGH",
		},
		{
			name: "Z8: range-zero on non-sensitive var - no finding",
			src: `package test
import "net/http"
func authorize(data []byte) {}
func ProcessCardCharge(w http.ResponseWriter, r *http.Request) {
	cardData := []byte("4111")
	buf := []byte("xx")
	for i := range buf {
		buf[i] = 0
	}
	authorize(cardData)
	w.Write([]byte("ok"))
}`,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// score cache is per-PackageInfo, not
			// global -- each subtest's pkgInfo carries a fresh cache.
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.src, parser.ParseComments)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}

			findings := detectZeroingTimingIssues(file, fset, "test.go")

			if len(findings) != tt.wantFindings {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantFindings)
				for i, f := range findings {
					t.Logf("  finding[%d]: %s %s %s", i, f.RuleID, f.Severity, f.Description)
				}
			}

			for _, wantRule := range tt.wantRuleIDs {
				found := false
				for _, f := range findings {
					if f.RuleID == wantRule {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected RuleID %s not found in findings", wantRule)
				}
			}

			if tt.wantSeverity != "" && len(findings) > 0 {
				for _, f := range findings {
					if string(f.Severity) != tt.wantSeverity {
						t.Errorf("got severity %s, want %s", f.Severity, tt.wantSeverity)
					}
				}
			}
		})
	}
}

// --- Scanner Integration ---

func TestRetentionScannerName(t *testing.T) {
	s := New()
	if s.Name() != "data_retention" {
		t.Errorf("got name %q, want %q", s.Name(), "data_retention")
	}
}

func TestRetentionScannerRequirements(t *testing.T) {
	s := New()
	reqs := s.Requirements()
	want := map[string]bool{"3.2.1": true, "3.3.1": true}
	for _, r := range reqs {
		if !want[r] {
			t.Errorf("unexpected requirement %q", r)
		}
		delete(want, r)
	}
	for r := range want {
		t.Errorf("missing requirement %q", r)
	}
}

func TestRetentionScannerRequirementInFindings(t *testing.T) {
	// Parse a source that should produce a finding and verify RequirementID.
	src := `package test
import "time"
type R struct{}
func (r *R) Set(ctx interface{}, key string, value interface{}, ttl time.Duration) {}
func example() {
	rdb := &R{}
	cardData := "4111"
	rdb.Set(nil, "card_data", cardData, 0)
}`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	aliases := resolveImportAliases(file)
	findings := detectRedisWithoutTTL(file, fset, "test.go", aliases)
	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding")
	}
	for _, f := range findings {
		if !strings.Contains(f.RequirementID, "3.2.1") {
			t.Errorf("expected RequirementID to contain 3.2.1, got %q", f.RequirementID)
		}
	}
}
