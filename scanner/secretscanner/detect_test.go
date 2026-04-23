package secretscanner

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// testdataDir returns the absolute path to the testdata directory.
func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file location")
	}
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}

// TestParseEnvFile tests the.env file parser.
func TestParseEnvFile(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.env")

	kvs, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("ParseEnvFile(%q) error: %v", path, err)
	}

	// Expected non-empty keys from secrets.env:
	// DB_PASSWORD, API_KEY, GITHUB_TOKEN, AWS_ACCESS_KEY_ID, PLACEHOLDER_KEY,
	// SHORT_VAL, DATABASE_URL, REDIS_URL, CLEAN_VALUE
	// EMPTY_KEY has empty value and should be skipped.
	expectedKeys := map[string]bool{
		"DB_PASSWORD":       true,
		"API_KEY":           true,
		"GITHUB_TOKEN":      true,
		"AWS_ACCESS_KEY_ID": true,
		"PLACEHOLDER_KEY":   true,
		"SHORT_VAL":         true,
		"DATABASE_URL":      true,
		"REDIS_URL":         true,
		"CLEAN_VALUE":       true,
	}

	foundKeys := make(map[string]bool)
	for _, kv := range kvs {
		foundKeys[kv.Key] = true
		if kv.FilePath != path {
			t.Errorf("KeyValue.FilePath = %q, want %q", kv.FilePath, path)
		}
		if kv.Line <= 0 {
			t.Errorf("KeyValue for key %q has Line=%d, want > 0", kv.Key, kv.Line)
		}
		if kv.Value == "" {
			t.Errorf("KeyValue for key %q should not have empty value (empty values are skipped)", kv.Key)
		}
	}

	for key := range expectedKeys {
		if !foundKeys[key] {
			t.Errorf("missing expected key %q", key)
		}
	}

	// EMPTY_KEY should NOT be in the results.
	if foundKeys["EMPTY_KEY"] {
		t.Error("EMPTY_KEY should be skipped (empty value)")
	}
}

func TestParseEnvFile_ExportPrefix(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.env")

	kvs, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile error: %v", err)
	}

	// "export AWS_ACCESS_KEY_ID=..." should parse as key "AWS_ACCESS_KEY_ID"
	found := false
	for _, kv := range kvs {
		if kv.Key == "AWS_ACCESS_KEY_ID" {
			found = true
			if kv.Value != "AKIAIOSFODNN7EXAMPLE" {
				t.Errorf("AWS_ACCESS_KEY_ID value = %q, want %q", kv.Value, "AKIAIOSFODNN7EXAMPLE")
			}
			break
		}
	}
	if !found {
		t.Error("AWS_ACCESS_KEY_ID not found (export prefix should be stripped)")
	}
}

func TestParseEnvFile_LineNumbers(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.env")

	kvs, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile error: %v", err)
	}

	// DB_PASSWORD is on line 2 (line 1 is a comment)
	for _, kv := range kvs {
		if kv.Key == "DB_PASSWORD" {
			if kv.Line != 2 {
				t.Errorf("DB_PASSWORD line = %d, want 2", kv.Line)
			}
			break
		}
	}
}

func TestParseEnvFile_NonexistentFile(t *testing.T) {
	t.Parallel()
	_, err := ParseEnvFile("/nonexistent/path/to/file.env")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

// TestParseYAMLFile tests the YAML parser with nested keys and line numbers.
func TestParseYAMLFile(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.yaml")

	kvs, err := ParseYAMLFile(path)
	if err != nil {
		t.Fatalf("ParseYAMLFile(%q) error: %v", path, err)
	}

	// Expected dot-separated keys with non-empty values.
	expectedKeys := map[string]string{
		"database.host":              "db.example.com",
		"database.password":          "SuperSecretYamlPass!",
		"database.connection_string": "mongodb://admin:mongopass@mongo.example.com:27017/payments",
		"api.stripe_key":             "sk_live_yamlstripekey1234567890abcdef",
		"api.google_key":             "AIzaSyB_fake_google_api_key_12345678",
		"api.placeholder":            "<your-api-key>",
		"payment.encryption_key":     "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
	}

	found := make(map[string]KeyValue)
	for _, kv := range kvs {
		found[kv.Key] = kv
	}

	for key, expectedVal := range expectedKeys {
		kv, ok := found[key]
		if !ok {
			t.Errorf("missing expected key %q", key)
			continue
		}
		if kv.Value != expectedVal {
			t.Errorf("key %q: value = %q, want %q", key, kv.Value, expectedVal)
		}
		if kv.Line <= 0 {
			t.Errorf("key %q: line = %d, want > 0 (YAML should have line numbers)", key, kv.Line)
		}
	}

	// "api.empty" should NOT be in results (empty string).
	if _, ok := found["api.empty"]; ok {
		t.Error("api.empty should be skipped (empty value)")
	}
}

func TestParseYAMLFile_LineNumbers(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.yaml")

	kvs, err := ParseYAMLFile(path)
	if err != nil {
		t.Fatalf("parseYAMLFile error: %v", err)
	}

	// "database.password" should be on line 3
	for _, kv := range kvs {
		if kv.Key == "database.password" {
			if kv.Line != 3 {
				t.Errorf("database.password line = %d, want 3", kv.Line)
			}
			break
		}
	}
}

// TestParseJSONFile tests the JSON parser with nested keys.
func TestParseJSONFile(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.json")

	kvs, err := ParseJSONFile(path)
	if err != nil {
		t.Fatalf("ParseJSONFile(%q) error: %v", path, err)
	}

	expectedKeys := map[string]string{
		"database.password": "JsonDbPassword123!",
		"database.url":      "mysql://root:rootpass@mysql.example.com:3306/payments",
		"api.token":         "ghp_jsontoken1234567890abcdefghijklmnopq",
		"api.clean":         "https://api.example.com",
	}

	found := make(map[string]KeyValue)
	for _, kv := range kvs {
		found[kv.Key] = kv
	}

	for key, expectedVal := range expectedKeys {
		kv, ok := found[key]
		if !ok {
			t.Errorf("missing expected key %q", key)
			continue
		}
		if kv.Value != expectedVal {
			t.Errorf("key %q: value = %q, want %q", key, kv.Value, expectedVal)
		}
		// JSON line is 0 (limitation).
		if kv.Line != 0 {
			t.Errorf("key %q: JSON line should be 0, got %d", key, kv.Line)
		}
	}

	// "api.placeholder" has value "xxx" which is non-empty but only 3 chars.
	// The parser should still include it; filtering is done by the detection engine.
	if kv, ok := found["api.placeholder"]; ok {
		if kv.Value != "xxx" {
			t.Errorf("api.placeholder value = %q, want %q", kv.Value, "xxx")
		}
	} else {
		t.Error("api.placeholder should be present (non-empty value)")
	}
}

// TestParseTOMLFile tests the TOML parser with nested keys and type conversion.
func TestParseTOMLFile(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.toml")

	kvs, err := ParseTOMLFile(path)
	if err != nil {
		t.Fatalf("ParseTOMLFile(%q) error: %v", path, err)
	}

	expectedKeys := map[string]string{
		"database.password": "TomlSecretPass456!",
		"api.secret_key":    "sk_test_tomlsecretkey1234567890abcdef",
		"redis.url":         "redis://:tomlredispass@redis.example.com:6379",
	}

	found := make(map[string]KeyValue)
	for _, kv := range kvs {
		found[kv.Key] = kv
	}

	for key, expectedVal := range expectedKeys {
		kv, ok := found[key]
		if !ok {
			t.Errorf("missing expected key %q", key)
			continue
		}
		if kv.Value != expectedVal {
			t.Errorf("key %q: value = %q, want %q", key, kv.Value, expectedVal)
		}
	}

	// Non-string types should be converted: port=5432 -> "5432"
	if kv, ok := found["database.port"]; ok {
		if kv.Value != "5432" {
			t.Errorf("database.port value = %q, want %q", kv.Value, "5432")
		}
	} else {
		t.Error("database.port should be present (int converted to string)")
	}

	// Boolean: enabled = true -> "true"
	if kv, ok := found["api.enabled"]; ok {
		if kv.Value != "true" {
			t.Errorf("api.enabled value = %q, want %q", kv.Value, "true")
		}
	} else {
		t.Error("api.enabled should be present (bool converted to string)")
	}

	// timeout = 30 -> "30"
	if kv, ok := found["api.timeout"]; ok {
		if kv.Value != "30" {
			t.Errorf("api.timeout value = %q, want %q", kv.Value, "30")
		}
	} else {
		t.Error("api.timeout should be present (int converted to string)")
	}
}

// --- SQL Query Exclusion ---

func TestSQLExclusion(t *testing.T) {
	t.Parallel()
	t.Run("isSQLQuery unit tests", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			want  bool
		}{
			{"SELECT", "SELECT balance FROM accounts WHERE card_hash = $1", true},
			{"INSERT INTO", "INSERT INTO payments (amount) VALUES ($1)", true},
			{"UPDATE", "UPDATE users SET name = $1 WHERE id = $2", true},
			{"DELETE FROM", "DELETE FROM sessions WHERE expired_at < NOW()", true},
			{"CREATE", "CREATE TABLE cards (id UUID PRIMARY KEY)", true},
			{"DROP", "DROP TABLE IF EXISTS temp_tokens", true},
			{"ALTER", "ALTER TABLE payments ADD COLUMN status TEXT", true},
			{"WITH", "WITH cte AS (SELECT * FROM orders)", true},
			{"leading whitespace", "  SELECT * FROM payments", true},
			{"case insensitive", "select * from payments", true},

			{"secret prefix", "sk_live_abc123secret456", false},
			{"hex string", "abcdef1234567890abcdef1234567890", false},
			{"random string", "some random value", false},
			{"empty", "", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := isSQLQuery(tt.input)
				if got != tt.want {
					t.Errorf("isSQLQuery(%q) = %v, want %v", tt.input, got, tt.want)
				}
			})
		}
	})

	t.Run("analyzeKeyValue excludes SQL query", func(t *testing.T) {
		kv := KeyValue{
			Key:      "query",
			Value:    "SELECT * FROM payments WHERE id = $1",
			Line:     1,
			FilePath: "test.yaml",
		}
		findings := analyzeKeyValue(kv)
		if len(findings) != 0 {
			t.Errorf("expected no findings for SQL query value, got %d: %v", len(findings), findings)
		}
	})

	t.Run("analyzeKeyValue excludes SQL even for credential key", func(t *testing.T) {
		kv := KeyValue{
			Key:      "password",
			Value:    "SELECT * FROM users",
			Line:     1,
			FilePath: "test.yaml",
		}
		findings := analyzeKeyValue(kv)
		if len(findings) != 0 {
			t.Errorf("expected no findings for SQL value in credential key, got %d: %v", len(findings), findings)
		}
	})

	t.Run("analyzeKeyValue still detects prefix in non-SQL value", func(t *testing.T) {
		kv := KeyValue{
			Key:      "password",
			Value:    "sk_live_abc123secretkeyvalue123456789012",
			Line:     1,
			FilePath: "test.yaml",
		}
		findings := analyzeKeyValue(kv)
		hasPrefixFinding := false
		for _, f := range findings {
			if f.RuleID == "SEC-PREFIX" {
				hasPrefixFinding = true
			}
		}
		if !hasPrefixFinding {
			t.Errorf("expected SEC-PREFIX finding for sk_live_ value, got: %v", findings)
		}
	})

	t.Run("analyzeKeyValue basic placeholder still filtered", func(t *testing.T) {
		kv := KeyValue{
			Key:      "db_query",
			Value:    "short",
			Line:     1,
			FilePath: "test.yaml",
		}
		findings := analyzeKeyValue(kv)
		if len(findings) != 0 {
			t.Errorf("expected no findings for short value, got %d: %v", len(findings), findings)
		}
	})
}

func TestParseEnvFile_SkipsEmptyValues(t *testing.T) {
	t.Parallel()
	dir := testdataDir(t)
	path := filepath.Join(dir, "secrets.env")

	kvs, err := ParseEnvFile(path)
	if err != nil {
		t.Fatalf("parseEnvFile error: %v", err)
	}

	for _, kv := range kvs {
		if kv.Value == "" {
			t.Errorf("found KeyValue with empty value for key %q -- parser should skip empty values", kv.Key)
		}
	}
}

// TestAnalyzeKeyValue_DedicatedDevDowngradesToInfo verifies:
// findings in dedicated-dev directories (dev/local/configs/...) are downgraded
// to SeverityInfo -- one tier below regular dev-context (Medium).
func TestAnalyzeKeyValue_DedicatedDevDowngradesToInfo(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "DATABASE_PASSWORD",
		Value:    "actual-looking-pwd-1234",
		Line:     1,
		FilePath: "dev/local/configs/service.env",
	}
	findings := analyzeKeyValue(kv)
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding for credential key, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.SeverityInfo {
			t.Errorf("finding %s severity = %q, want %q (dedicated-dev should downgrade to Info)",
				f.RuleID, f.Severity, scanner.SeverityInfo)
		}
		if !f.DevContext {
			t.Errorf("finding %s DevContext = false, want true (dedicated-dev must set flag)", f.RuleID)
		}
	}
}

// TestAnalyzeKeyValue_RegularDevDowngradeStaysMedium verifies:
// a regular dev-context segment ("fixtures/") still only downgrades ONE tier
// (Medium), not to Info. "testdata" was removed from devPathSegments in// uses "fixtures/" instead.
func TestAnalyzeKeyValue_RegularDevDowngradeStaysMedium(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "DATABASE_PASSWORD",
		Value:    "actual-looking-pwd-1234",
		Line:     1,
		FilePath: "internal/fixtures/test.env",
	}
	findings := analyzeKeyValue(kv)
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding for credential key, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.SeverityMedium {
			t.Errorf("finding %s severity = %q, want %q (regular dev-context is one-tier downgrade)",
				f.RuleID, f.Severity, scanner.SeverityMedium)
		}
	}
}

// TestAnalyzeKeyValue_TestdataStaysAtOriginalSeverity verifies the Bug 2 fix:
// "testdata" is no longer a dev marker, so credentials in testdata/ paths
// retain their original severity. This is the regression guard for the
// golden fixture silently downgrading when scanned from within the repo.
func TestAnalyzeKeyValue_TestdataStaysAtOriginalSeverity(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "DATABASE_PASSWORD",
		Value:    "actual-looking-pwd-1234",
		Line:     1,
		FilePath: "internal/testdata/test.env",
	}
	findings := analyzeKeyValue(kv)
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding for credential key, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.SeverityCritical {
			t.Errorf("finding %s severity = %q, want %q (testdata/ no longer triggers dev-context downgrade)",
				f.RuleID, f.Severity, scanner.SeverityCritical)
		}
	}
}

// TestAnalyzeKeyValue_ProdOverrideStaysCritical verifies that an
// attacker cannot bypass prod override by placing a "dev" segment inside
// a config/prod/ path -- prod-path short-circuit must win.
func TestAnalyzeKeyValue_ProdOverrideStaysCritical(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "DATABASE_PASSWORD",
		Value:    "actual-looking-pwd-1234",
		Line:     1,
		FilePath: "config/prod/service.env",
	}
	findings := analyzeKeyValue(kv)
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding for credential key, got none")
	}
	for _, f := range findings {
		if f.Severity != scanner.SeverityCritical {
			t.Errorf("finding %s severity = %q, want %q (prod path must stay Critical)",
				f.RuleID, f.Severity, scanner.SeverityCritical)
		}
	}
}

// ---: path/URL value-shape discriminator ---

// TestAnalyzeKeyValue_SkipPathValueForPathSuffix verifies that keys ending in
// *_PATH, *_DIR, *_FILE, *_LOCATION whose values look like filesystem paths
// are NOT flagged as SEC-CREDENTIAL-KEY.
func TestAnalyzeKeyValue_SkipPathValueForPathSuffix(t *testing.T) {
	t.Parallel()
	cases := []KeyValue{
		{Key: "VAULT_SECRETS_PATH", Value: "/vault/v1/secrets/data", Line: 1, FilePath: "config/service.env"},
		{Key: "TOKEN_EXPIRATION_STRATEGY_PATH", Value: "/tokens/exp/strategy", Line: 1, FilePath: "config/service.env"},
		{Key: "config.file.path", Value: "/etc/myapp/config.yaml", Line: 1, FilePath: "config/service.yaml"},
	}
	for _, kv := range cases {
		t.Run(kv.Key, func(t *testing.T) {
			findings := analyzeKeyValue(kv)
			for _, f := range findings {
				if f.RuleID == "SEC-CREDENTIAL-KEY" || f.RuleID == "SEC-HIGH-ENTROPY" {
					t.Errorf("unexpected %s finding for %q=%q: path/URL discriminator should have skipped it",
						f.RuleID, kv.Key, kv.Value)
				}
			}
		})
	}
}

// TestAnalyzeKeyValue_SkipURLValueForURLSuffix verifies that keys ending in
// *_URL, *_URI, *_ENDPOINT, *_HOST whose values look like URLs or hostnames
// are NOT flagged as SEC-CREDENTIAL-KEY.
func TestAnalyzeKeyValue_SkipURLValueForURLSuffix(t *testing.T) {
	t.Parallel()
	cases := []KeyValue{
		{Key: "VTS_AUTH_URL", Value: "https://vts.example.com/auth", Line: 1, FilePath: "config/service.env"},
		{Key: "API_ENDPOINT", Value: "https://api.example.com/v1", Line: 1, FilePath: "config/service.env"},
		{Key: "DB_HOST", Value: "db.internal.example.com", Line: 1, FilePath: "config/service.env"},
	}
	for _, kv := range cases {
		t.Run(kv.Key, func(t *testing.T) {
			findings := analyzeKeyValue(kv)
			for _, f := range findings {
				if f.RuleID == "SEC-CREDENTIAL-KEY" || f.RuleID == "SEC-HIGH-ENTROPY" {
					t.Errorf("unexpected %s finding for %q=%q: path/URL discriminator should have skipped it",
						f.RuleID, kv.Key, kv.Value)
				}
			}
		})
	}
}

// TestAnalyzeKeyValue_StillFlagsRealSecretsOnCredentialKey verifies the
// discriminator does NOT over-broaden: real credential keys with non-path
// values still fire SEC-CREDENTIAL-KEY.
func TestAnalyzeKeyValue_StillFlagsRealSecretsOnCredentialKey(t *testing.T) {
	t.Parallel()
	cases := []KeyValue{
		{Key: "DATABASE_PASSWORD", Value: "real-looking-pass-1234", Line: 1, FilePath: "config/prod/service.env"},
		{Key: "API_TOKEN", Value: "abc123xyz789", Line: 1, FilePath: "config/prod/service.env"},
	}
	for _, kv := range cases {
		t.Run(kv.Key, func(t *testing.T) {
			findings := analyzeKeyValue(kv)
			hasCredKey := false
			for _, f := range findings {
				if f.RuleID == "SEC-CREDENTIAL-KEY" {
					hasCredKey = true
					break
				}
			}
			if !hasCredKey {
				t.Errorf("expected SEC-CREDENTIAL-KEY for %q=%q; got findings=%v", kv.Key, kv.Value, findings)
			}
		})
	}
}

// TestAnalyzeKeyValue_SuffixIsPrefixNotSuffix verifies that PATH_SECRET
// (PATH is a prefix, not a suffix) still fires SEC-CREDENTIAL-KEY -- the
// discriminator is suffix-only.
func TestAnalyzeKeyValue_SuffixIsPrefixNotSuffix(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "PATH_SECRET",
		Value:    "xyz12345abcdefgh",
		Line:     1,
		FilePath: "config/prod/service.env",
	}
	findings := analyzeKeyValue(kv)
	hasCredKey := false
	for _, f := range findings {
		if f.RuleID == "SEC-CREDENTIAL-KEY" {
			hasCredKey = true
			break
		}
	}
	if !hasCredKey {
		t.Errorf("expected SEC-CREDENTIAL-KEY for %q=%q (prefix should not match suffix gate); got %v",
			kv.Key, kv.Value, findings)
	}
}

// --- FP5-01.: Relative path recognition without./ prefix ---

func TestIsPathOrURLValue_RelativePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		val  string
		want bool
	}{
		// Positive: >=3 segments, looks like filesystem path
		{"vault relative path", "vault/myapp/dynamic/myapp-secret", true},
		{"dev strategy json", "dev/local/expirationstrategy/strategy.json", true},
		{"three segments", "a/b/c", true},
		{"dotted segments", "vault/v2.1/config.yaml", true},

		// Negative: not enough segments
		{"single word", "simple-word", false},
		{"two segments only", "two/segments", false},

		// Negative: token-like (base64 guard)
		{"base64 segment", "aGVsbG8gd29ybGQbase64/token/more", false},

		// Negative: not a path
		{"stripe secret", "sk_live_abc123def456", false},
		{"spaces", "has spaces/in/path", false},

		// regression: real secret in *_PATH key must still fire
		// (this tests the value only, not the key; SEC-PREFIX fires first)
		{"short alphanum no slashes", "sk_live_abc123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPathOrURLValue(tt.val)
			if got != tt.want {
				t.Errorf("isPathOrURLValue(%q) = %v, want %v", tt.val, got, tt.want)
			}
		})
	}
}

// TestAnalyzeKeyValue_RelativePathSkipsCredentialKey verifies: values
// paths and skip SEC-CREDENTIAL-KEY when key has path suffix.
func TestAnalyzeKeyValue_RelativePathSkipsCredentialKey(t *testing.T) {
	t.Parallel()
	cases := []KeyValue{
		{Key: "VAULT_SECRETS_PATH", Value: "vault/myapp/dynamic/myapp-secret", Line: 1, FilePath: "config/service.env"},
		{Key: "TOKEN_EXPIRATION_STRATEGY_PATH", Value: "dev/local/expirationstrategy/strategy.json", Line: 1, FilePath: "config/service.env"},
	}
	for _, kv := range cases {
		t.Run(kv.Key, func(t *testing.T) {
			findings := analyzeKeyValue(kv)
			for _, f := range findings {
				if f.RuleID == "SEC-CREDENTIAL-KEY" || f.RuleID == "SEC-HIGH-ENTROPY" {
					t.Errorf("unexpected %s finding for %q=%q: relative path discriminator should have skipped it",
						f.RuleID, kv.Key, kv.Value)
				}
			}
		})
	}
}

// TestAnalyzeKeyValue_RealSecretInPathKey verifies regression:
// SEC-PREFIX still fires for real secrets even in *_PATH keys.
func TestAnalyzeKeyValue_RealSecretInPathKey(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "SECRET_PATH",
		Value:    "sk_live_abc123secretkeyvalue123456789012",
		Line:     1,
		FilePath: "config/service.env",
	}
	findings := analyzeKeyValue(kv)
	hasPrefixFinding := false
	for _, f := range findings {
		if f.RuleID == "SEC-PREFIX" {
			hasPrefixFinding = true
		}
	}
	if !hasPrefixFinding {
		t.Errorf("expected SEC-PREFIX finding for real secret in *_PATH key, got: %v", findings)
	}
}

// TestAnalyzeKeyValue_PathSuffixButValueNotPath verifies the discriminator is
// CONSERVATIVE: if the key suffix is path/url-like but the value does NOT
// confidently look like a path or URL, SEC-CREDENTIAL-KEY still fires.
// NOTE: "kv/data/prod_database_pwd" is now correctly recognized as a relative
// path, so we use a value without slashes to test the conservative case.
func TestAnalyzeKeyValue_PathSuffixButValueNotPath(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "SECRETS_PATH",
		Value:    "prod_database_pwd_secret",
		Line:     1,
		FilePath: "config/prod/service.env",
	}
	findings := analyzeKeyValue(kv)
	hasCredKey := false
	for _, f := range findings {
		if f.RuleID == "SEC-CREDENTIAL-KEY" {
			hasCredKey = true
			break
		}
	}
	if !hasCredKey {
		t.Errorf("expected SEC-CREDENTIAL-KEY for %q=%q (value is ambiguous — NOT a confident path/URL); got %v",
			kv.Key, kv.Value, findings)
	}
}

// TestAnalyzeKeyValue_VaultPathSkipsCredentialKey verifies that Vault KV paths
// like "kv/data/prod_database_pwd" are correctly recognized as relative paths
// and skip SEC-CREDENTIAL-KEY when the key has a path suffix.
func TestAnalyzeKeyValue_VaultPathSkipsCredentialKey(t *testing.T) {
	t.Parallel()
	kv := KeyValue{
		Key:      "SECRETS_PATH",
		Value:    "kv/data/prod_database_pwd",
		Line:     1,
		FilePath: "config/prod/service.env",
	}
	findings := analyzeKeyValue(kv)
	for _, f := range findings {
		if f.RuleID == "SEC-CREDENTIAL-KEY" {
			t.Errorf("unexpected SEC-CREDENTIAL-KEY for Vault path %q=%q: relative path discriminator should skip it",
				kv.Key, kv.Value)
		}
	}
}

// TestAnalyzeKeyValueExamplesPathTriageHint verifies F-24: credentials in
// examples/ directories downgrade to INFO and carry the
// dev_path_examples_skipped TriageHint. Production-path credentials stay
// CRITICAL with no TriageHint.
func TestAnalyzeKeyValueExamplesPathTriageHint(t *testing.T) {
	t.Parallel()
	t.Run("examples_dir_downgrades_with_triage_hint", func(t *testing.T) {
		kv := KeyValue{
			Key:      "api_key",
			Value:    "abcdef1234567890abcdef",
			Line:     2,
			FilePath: "clean/examples/api-example.env.json",
		}
		findings := analyzeKeyValue(kv)
		if len(findings) == 0 {
			t.Fatalf("expected at least one finding for credential key in examples dir")
		}
		for _, f := range findings {
			if f.RuleID != "SEC-CREDENTIAL-KEY" {
				continue
			}
			if f.Severity != scanner.SeverityInfo {
				t.Errorf("severity = %q, want %q (examples dir must downgrade to INFO)",
					f.Severity, scanner.SeverityInfo)
			}
			if !f.DevContext {
				t.Errorf("DevContext = false, want true (examples dir must set flag)")
			}
			if f.TriageHint != "dev_path_examples_skipped" {
				t.Errorf("TriageHint = %q, want %q", f.TriageHint, "dev_path_examples_skipped")
			}
		}
	})

	t.Run("prod_configs_stays_critical_no_triage_hint", func(t *testing.T) {
		kv := KeyValue{
			Key:      "api_key",
			Value:    "abcdef1234567890abcdef",
			Line:     2,
			FilePath: "configs/prod-api-key.json",
		}
		findings := analyzeKeyValue(kv)
		if len(findings) == 0 {
			t.Fatalf("expected at least one finding for credential key in prod configs path")
		}
		for _, f := range findings {
			if f.RuleID != "SEC-CREDENTIAL-KEY" {
				continue
			}
			if f.Severity != scanner.SeverityCritical {
				t.Errorf("severity = %q, want %q (configs/ path must stay CRITICAL)",
					f.Severity, scanner.SeverityCritical)
			}
			if f.TriageHint != "" {
				t.Errorf("TriageHint = %q, want empty (prod path must not set examples hint)", f.TriageHint)
			}
		}
	})
}
