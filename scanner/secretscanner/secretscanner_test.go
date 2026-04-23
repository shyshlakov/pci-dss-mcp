package secretscanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestAnalyzeKeyValue_KnownPrefixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		kv       KeyValue
		wantRule string
		wantSev  scanner.Severity
	}{
		{
			name:     "sk_live_ prefix (Stripe)",
			kv:       KeyValue{Key: "api_key", Value: "sk_live_abcdefghijklmnopqrstuvwxyz1234", FilePath: "test.env", Line: 1},
			wantRule: "SEC-PREFIX",
			wantSev:  scanner.SeverityCritical,
		},
		{
			name:     "ghp_ prefix (GitHub PAT)",
			kv:       KeyValue{Key: "token", Value: "ghp_1234567890abcdefghijklmnopqrstuvwxyz1", FilePath: "test.env", Line: 2},
			wantRule: "SEC-PREFIX",
			wantSev:  scanner.SeverityCritical,
		},
		{
			name:     "AKIA prefix (AWS)",
			kv:       KeyValue{Key: "aws_key", Value: "AKIAIOSFODNN7EXAMPLE", FilePath: "test.env", Line: 3},
			wantRule: "SEC-PREFIX",
			wantSev:  scanner.SeverityCritical,
		},
		{
			name:     "AIza prefix (Google)",
			kv:       KeyValue{Key: "google_key", Value: "AIzaSyB_fake_google_api_key_1234567890a", FilePath: "test.env", Line: 4},
			wantRule: "SEC-PREFIX",
			wantSev:  scanner.SeverityCritical,
		},
		{
			name:     "AKIA too short -- must be at least 20 chars",
			kv:       KeyValue{Key: "aws_key", Value: "AKIA1234567890", FilePath: "test.env", Line: 5},
			wantRule: "", // should not match: too short
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeKeyValue(tt.kv)
			if tt.wantRule == "" {
				// Check that no SEC-PREFIX finding exists.
				for _, f := range findings {
					if f.RuleID == "SEC-PREFIX" {
						t.Errorf("expected no SEC-PREFIX finding, got one: %s", f.Description)
					}
				}
				return
			}
			found := false
			for _, f := range findings {
				if f.RuleID == tt.wantRule && f.Severity == tt.wantSev {
					found = true
					if f.RequirementID != "8.6.2" {
						t.Errorf("RequirementID = %q, want %q", f.RequirementID, "8.6.2")
					}
					break
				}
			}
			if !found {
				t.Errorf("expected finding with RuleID=%q, Severity=%q; got %v", tt.wantRule, tt.wantSev, findings)
			}
		})
	}
}

func TestAnalyzeKeyValue_CredentialKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		kv       KeyValue
		wantRule string
	}{
		{
			name:     "password key",
			kv:       KeyValue{Key: "database.password", Value: "SuperSecretPass123!", FilePath: "test.yaml", Line: 3},
			wantRule: "SEC-CREDENTIAL-KEY",
		},
		{
			name:     "api_key key",
			kv:       KeyValue{Key: "api_key", Value: "some_value_here_1234", FilePath: "test.env", Line: 1},
			wantRule: "SEC-CREDENTIAL-KEY",
		},
		{
			name:     "secret key",
			kv:       KeyValue{Key: "app.secret", Value: "my_secret_value_1234", FilePath: "test.yaml", Line: 5},
			wantRule: "SEC-CREDENTIAL-KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeKeyValue(tt.kv)
			found := false
			for _, f := range findings {
				if f.RuleID == tt.wantRule {
					found = true
					if f.Severity != scanner.SeverityCritical {
						t.Errorf("Severity = %q, want CRITICAL", f.Severity)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected finding with RuleID=%q; got %v", tt.wantRule, findings)
			}
		})
	}
}

func TestAnalyzeKeyValue_HighEntropy(t *testing.T) {
	t.Parallel()
	// A random-looking value in a credential key context: Shannon > 4.5, len >= 16.
	// Uses mixed case + digits to achieve high entropy (~4.7 bits/char).
	kv := KeyValue{
		Key:      "payment.secret_key",
		Value:    "Kx9Mp2LvB5nQ8rTjW3sY7fAzE1cG",
		FilePath: "test.yaml",
		Line:     10,
	}
	findings := analyzeKeyValue(kv)
	found := false
	for _, f := range findings {
		if f.RuleID == "SEC-HIGH-ENTROPY" {
			found = true
			if f.Severity != scanner.SeverityHigh {
				t.Errorf("Severity = %q, want HIGH", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected SEC-HIGH-ENTROPY finding for high-entropy value in credential key context; got %v", findings)
	}
}

func TestAnalyzeKeyValue_ConnectionStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value string
	}{
		{"postgres", "postgres://admin:s3cret@db.example.com:5432/payments"},
		{"mysql", "mysql://root:rootpass@mysql.example.com:3306/payments"},
		{"mongodb", "mongodb://admin:mongopass@mongo.example.com:27017/payments"},
		{"mongodb+srv", "mongodb+srv://admin:mongopass@mongo.example.com/payments"},
		{"redis", "redis://:mypassword@redis.example.com:6379"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kv := KeyValue{Key: "db_url", Value: tt.value, FilePath: "test.env", Line: 1}
			findings := analyzeKeyValue(kv)
			found := false
			for _, f := range findings {
				if f.RuleID == "SEC-CONNSTR" {
					found = true
					if f.Severity != scanner.SeverityCritical {
						t.Errorf("Severity = %q, want CRITICAL", f.Severity)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected SEC-CONNSTR finding for %q; got %v", tt.value, findings)
			}
		})
	}
}

func TestAnalyzeKeyValue_Exclusions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kv   KeyValue
	}{
		{
			name: "empty value",
			kv:   KeyValue{Key: "password", Value: "", FilePath: "test.env", Line: 1},
		},
		{
			name: "changeme placeholder",
			kv:   KeyValue{Key: "password", Value: "changeme", FilePath: "test.env", Line: 2},
		},
		{
			name: "xxx placeholder",
			kv:   KeyValue{Key: "api_key", Value: "xxx", FilePath: "test.env", Line: 3},
		},
		{
			name: "TODO placeholder",
			kv:   KeyValue{Key: "secret", Value: "TODO", FilePath: "test.env", Line: 4},
		},
		{
			name: "short value (< 4 chars)",
			kv:   KeyValue{Key: "api_key", Value: "abc", FilePath: "test.env", Line: 5},
		},
		{
			name: "angle bracket placeholder",
			kv:   KeyValue{Key: "api_key", Value: "<your-api-key>", FilePath: "test.yaml", Line: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeKeyValue(tt.kv)
			if len(findings) > 0 {
				t.Errorf("expected 0 findings for excluded value %q, got %d: %v", tt.kv.Value, len(findings), findings)
			}
		})
	}
}

func TestSecretsScanner_ScanWithExclusions_AllFormats(t *testing.T) {
	t.Parallel()
	// Copy fixtures to a temp dir because the walker excludes "testdata" directories.
	srcDir := testdataDir(t)
	tmpDir := t.TempDir()
	fixtureFiles := []string{"secrets.env", "secrets.yaml", "secrets.json", "secrets.toml"}
	for _, name := range fixtureFiles {
		data, err := readFileBytes(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("reading fixture %s: %v", name, err)
		}
		if err := writeFileBytes(filepath.Join(tmpDir, name), data); err != nil {
			t.Fatalf("writing fixture %s: %v", name, err)
		}
	}

	s := New()

	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("expected findings from fixtures, got 0")
	}

	// Check that we have findings from all four file types.
	fileExts := make(map[string]bool)
	for _, f := range result.Findings {
		ext := filepath.Ext(f.FilePath)
		fileExts[ext] = true
	}

	for _, ext := range []string{".env", ".yaml", ".json", ".toml"} {
		if !fileExts[ext] {
			t.Errorf("expected findings from %s files, found none", ext)
		}
	}

	// Metadata should have scanned files > 0
	if result.Metadata.ScannedFiles == 0 {
		t.Error("Metadata.ScannedFiles should be > 0")
	}
}

func TestSecretsScanner_ScanWithExclusions_CleanFile(t *testing.T) {
	t.Parallel()
	// Create a temp dir with only the clean file to avoid testdata exclusion.
	dir := t.TempDir()
	// Copy clean file to temp dir.
	src := filepath.Join(testdataDir(t), "secrets_clean.env")
	data, err := readFileBytes(src)
	if err != nil {
		t.Fatalf("reading clean file: %v", err)
	}
	dst := filepath.Join(dir, "secrets_clean.env")
	if err := writeFileBytes(dst, data); err != nil {
		t.Fatalf("writing clean file: %v", err)
	}

	s := New()
	result, err := s.ScanWithExclusions(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions error: %v", err)
	}

	if len(result.Findings) != 0 {
		var descs []string
		for _, f := range result.Findings {
			descs = append(descs, f.Description)
		}
		t.Errorf("expected 0 findings for clean config, got %d: %s", len(result.Findings), strings.Join(descs, "; "))
	}
}

func TestSecretsScanner_Name(t *testing.T) {
	t.Parallel()
	s := New()
	if s.Name() != "secrets" {
		t.Errorf("Name() = %q, want %q", s.Name(), "secrets")
	}
}

func TestSecretsScanner_Requirements(t *testing.T) {
	t.Parallel()
	s := New()
	reqs := s.Requirements()
	if len(reqs) == 0 || reqs[0] != "8.6.2" {
		t.Errorf("Requirements() = %v, want [\"8.6.2\"]", reqs)
	}
}
