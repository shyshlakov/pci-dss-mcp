// Package secretscanner implements a secrets scanner that detects hardcoded
// secrets in configuration files (.env,.yaml,.json,.toml).
//
// Detection methods:
// - SEC-PREFIX: Known secret prefixes (sk_, ghp_, AKIA, AIza, etc.)
// - SEC-CONNSTR: Database connection strings with embedded credentials
// - SEC-CREDENTIAL-KEY: Credential-named keys with non-empty values
// - SEC-HIGH-ENTROPY: High-entropy values in sensitive key context
//
// This scanner targets PCI DSS 8.6.2 -- system/application passwords must not
// be hardcoded in config files.
package secretscanner

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// KeyValue represents a parsed key-value pair from a config file.
// All format parsers (env, yaml, json, toml) produce KeyValue tuples
// that are fed into the detection engine.
type KeyValue struct {
	Key      string // Full dot-separated key path (e.g., "database.password")
	Value    string // The string value
	Line     int    // Line number in source file (0 if unavailable)
	FilePath string // Source file path
}

// secretPrefix defines a known secret prefix pattern with minimum length.
type secretPrefix struct {
	Name   string
	Prefix string
	MinLen int
}

// knownSecretPrefixes lists well-known API key/token prefixes and their
// minimum expected lengths.
var knownSecretPrefixes = []secretPrefix{
	{Name: "AWS Access Key", Prefix: "AKIA", MinLen: 20},
	{Name: "AWS Temporary Key", Prefix: "ASIA", MinLen: 20},
	{Name: "GitHub PAT", Prefix: "ghp_", MinLen: 40},
	{Name: "GitHub OAuth", Prefix: "gho_", MinLen: 40},
	{Name: "GitHub User-to-Server", Prefix: "ghu_", MinLen: 40},
	{Name: "GitHub Server-to-Server", Prefix: "ghs_", MinLen: 40},
	{Name: "GitHub Refresh", Prefix: "ghr_", MinLen: 40},
	{Name: "GitHub Fine-Grained PAT", Prefix: "github_pat_", MinLen: 82},
	{Name: "GitLab PAT", Prefix: "glpat-", MinLen: 26},
	{Name: "Stripe Live Secret", Prefix: "sk_live_", MinLen: 32},
	{Name: "Stripe Live Public", Prefix: "pk_live_", MinLen: 32},
	{Name: "Stripe Test Secret", Prefix: "sk_test_", MinLen: 32},
	{Name: "Stripe Restricted", Prefix: "rk_live_", MinLen: 32},
	{Name: "Google API Key", Prefix: "AIza", MinLen: 39},
	{Name: "Slack Bot Token", Prefix: "xoxb-", MinLen: 50},
	{Name: "Slack User Token", Prefix: "xoxp-", MinLen: 50},
	{Name: "Slack App Token", Prefix: "xoxa-", MinLen: 50},
	{Name: "Slack Socket Token", Prefix: "xoxs-", MinLen: 50},
	{Name: "Slack Refresh Token", Prefix: "xoxr-", MinLen: 50},
	{Name: "Anthropic API Key", Prefix: "sk-ant-", MinLen: 20},
	{Name: "NPM Token", Prefix: "npm_", MinLen: 36},
	{Name: "PyPI Token", Prefix: "pypi-", MinLen: 20},
	{Name: "Shopify Private App", Prefix: "shpat_", MinLen: 32},
	{Name: "Shopify Custom App", Prefix: "shpca_", MinLen: 32},
	{Name: "Shopify Partner App", Prefix: "shppa_", MinLen: 32},
	{Name: "SendGrid API Key", Prefix: "SG.", MinLen: 20},
	{Name: "NVIDIA API Key", Prefix: "nvapi-", MinLen: 20},
	{Name: "Groq API Key", Prefix: "gsk_", MinLen: 20},
}

// credentialKeySubstrings are substrings that indicate a key holds credential data.
// Matched against normalized (lowercase, no underscores/hyphens) key names.
var credentialKeySubstrings = []string{
	"password",
	"passwd",
	"secret",
	"apikey",
	"api_key",
	"token",
	"accesskey",
	"privatekey",
	"credential",
	"auth",
}

// placeholderExactValues are values that exactly match (case-insensitive)
// known placeholder patterns and should be excluded from detection.
var placeholderExactValues = []string{
	"xxx",
	"changeme",
	"todo",
	"fixme",
	"replace_me",
	"your_key",
	"your_secret",
	"your_token",
	"your_password",
	"example",
	"dummy",
	"test",
	"none",
	"null",
	"undefined",
	"n/a",
}

// placeholderSubstrings indicate a value is likely a placeholder when it
// contains these substrings. Only applied for lower-confidence checks
// (credential key, entropy) -- not for prefix or connection string checks.
var placeholderSubstrings = []string{
	"changeme",
	"replace_me",
	"your_",
	"fixme",
}

// connStringPatterns are regexes for connection strings with embedded credentials.
// Each requires a user:password@ portion to avoid false positives on scheme-only URLs.
var connStringPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^postgres(ql)?://[^:]+:[^@]+@`),
	regexp.MustCompile(`(?i)^mysql://[^:]+:[^@]+@`),
	regexp.MustCompile(`(?i)^mongodb(\+srv)?://[^:]+:[^@]+@`),
	regexp.MustCompile(`(?i)^redis://[^@]*:[^@]+@`),
	regexp.MustCompile(`(?i)^amqps?://[^:]+:[^@]+@`),
}

// sqlQueryPattern matches SQL statement prefixes. SQL queries are never
// secrets -- exclude before credential key or entropy analysis.
var sqlQueryPattern = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE|DROP|ALTER|WITH)\s+`)

// isSQLQuery returns true if the value looks like an SQL query string.
func isSQLQuery(val string) bool {
	return sqlQueryPattern.MatchString(val)
}

// pathURLKeySuffixes are case-insensitive suffixes on the LAST key segment.
// When the key suffix matches one of these AND the value looks like a path or
// URL (isPathOrURLValue), analyzeKeyValue skips SEC-CREDENTIAL-KEY and
// SEC-HIGH-ENTROPY for that key. High-confidence checks
// (SEC-PREFIX, SEC-CONNSTR) are unaffected because they run BEFORE this
// discriminator -- an attacker cannot hide a real secret behind a *_URL key.
var pathURLKeySuffixes = []string{
	"_path", "_dir", "_file", "_location",
	"_url", "_uri", "_endpoint", "_host",
}

// hostnameRE loosely matches values that look like `domain.tld` or
// `domain.tld/path`. At least two alpha-numeric segments separated by a dot.
// Uses bounded character classes to avoid catastrophic backtracking:
// a single pass over the string with no nested quantifiers.
var hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*(\.[a-zA-Z0-9-]+)+(/\S*)?$`)

// fileSystemPathRE matches absolute or nested filesystem paths.
// Accept: /etc/foo, /var/log/a.yaml,./config/x,./data/y, C:\Users\foo.
// Reject: single tokens, strings with spaces, strings with '=' or quotes.
var fileSystemPathRE = regexp.MustCompile(`^(/|\./|\.\./|[a-zA-Z]:[\\/])[^\s='"` + "`" + `]+$`)

// relativePathRE matches relative paths without./ prefix: at least 3
// slash-separated segments, each segment is alphanumeric with dots/hyphens/
var relativePathRE = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]*/[a-zA-Z0-9._-]+/[a-zA-Z0-9._/-]+$`)

// hasPathOrURLKeySuffix returns true if the last dot-segment of the key
// (case-insensitive) ends with one of pathURLKeySuffixes. Dot-segmentation
// matches how YAML/TOML parsers produce nested keys (e.g., "config.file.path").
func hasPathOrURLKeySuffix(key string) bool {
	parts := strings.Split(key, ".")
	last := strings.ToLower(parts[len(parts)-1])
	for _, suf := range pathURLKeySuffixes {
		if strings.HasSuffix(last, suf) {
			return true
		}
	}
	return false
}

// isPathOrURLValue returns true when val CONFIDENTLY looks like a path or URL:
// - begins with http://, https://, file://, s3://, gs://
// - matches fileSystemPathRE (/,./,./, or Windows drive)
// - matches hostnameRE (domain.tld or domain.tld/path)
//
// Values containing whitespace, `=`, or quote characters are always rejected
// as placeholder-like noise. The helper is deliberately conservative: when
// in doubt, we return false and let the credential-key check run.
func isPathOrURLValue(val string) bool {
	if val == "" || strings.ContainsAny(val, " \t='\"`") {
		return false
	}
	lower := strings.ToLower(val)
	if strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "file://") ||
		strings.HasPrefix(lower, "s3://") ||
		strings.HasPrefix(lower, "gs://") {
		return true
	}
	if fileSystemPathRE.MatchString(val) {
		return true
	}
	// relative paths without./ prefix (at least 3 segments, no base64 segments).
	if strings.Count(val, "/") >= 2 && relativePathRE.MatchString(val) && !looksLikeBase64Segment(val) {
		return true
	}
	if hostnameRE.MatchString(val) {
		return true
	}
	return false
}

// looksLikeBase64Segment returns true if any path segment is >=20 chars of
// pure alphanumeric characters (likely a token/secret, not a directory name).
// guard: prevents false path classification of token-like strings.
func looksLikeBase64Segment(val string) bool {
	for _, seg := range strings.Split(val, "/") {
		if len(seg) >= 20 && isAlphanumOnly(seg) {
			return true
		}
	}
	return false
}

// isAlphanumOnly returns true if s contains only ASCII alphanumeric chars.
func isAlphanumOnly(s string) bool {
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// isBasicPlaceholder returns true if the value is empty, too short, an exact
// placeholder match, or wrapped in angle brackets. Used as first-pass filter
// for ALL detection methods.
func isBasicPlaceholder(value string) bool {
	if value == "" {
		return true
	}
	if len(value) < 4 {
		return true
	}

	// Check angle bracket placeholders like <your-api-key>.
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return true
	}

	// Check exact placeholder values (case-insensitive).
	lower := strings.ToLower(value)
	for _, p := range placeholderExactValues {
		if lower == p {
			return true
		}
	}
	return false
}

// isSubstringPlaceholder returns true if the value contains placeholder
// substrings. This is a stricter filter applied only for lower-confidence
// checks (credential key names, entropy) to avoid false positives on
// values that happen to contain "example" or "test" in URLs/connection strings.
func isSubstringPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, p := range placeholderSubstrings {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// normalizeKey strips underscores and hyphens and lowercases for matching.
func normalizeKey(key string) string {
	// Take only the last segment of a dot-separated path.
	parts := strings.Split(key, ".")
	last := parts[len(parts)-1]
	lower := strings.ToLower(last)
	lower = strings.ReplaceAll(lower, "_", "")
	lower = strings.ReplaceAll(lower, "-", "")
	return lower
}

// isCredentialKey returns true if the key name matches known credential patterns.
func isCredentialKey(key string) bool {
	norm := normalizeKey(key)
	for _, sub := range credentialKeySubstrings {
		clean := strings.ReplaceAll(sub, "_", "")
		if strings.Contains(norm, clean) {
			return true
		}
	}
	return false
}

// isHighEntropy returns true when the value has sufficient length and Shannon
// entropy to suggest it is a random secret.
func isHighEntropy(value string) bool {
	return len(value) >= 16 && scanner.ShannonEntropy(value) > 4.5
}

// analyzeKeyValue is the legacy entry point that delegates to
// analyzeKeyValueInRoot with an empty scan root. Kept for the in-package
// test suite that predates the project-root-aware devcontext fix.
func analyzeKeyValue(kv KeyValue) []scanner.Finding {
	return analyzeKeyValueInRoot(kv, "")
}

// analyzeKeyValueInRoot applies all detection methods to a single KeyValue and
// returns any findings. Returns nil if no secrets detected. projectRoot is
// plumbed through to scanner.ClassifyDevContextInRoot so ancestor directory
// segments are stripped before dev-path matching.
//
// Detection order:
// 1. Skip basic placeholders (empty, short, angle brackets, exact matches)
// 2. Known prefixes (SEC-PREFIX, CRITICAL) -- high confidence, no substring filter
// 3. Connection strings (SEC-CONNSTR, CRITICAL) -- high confidence, no substring filter
// 4. Skip substring placeholders for remaining lower-confidence checks
// 5. Credential key names (SEC-CREDENTIAL-KEY, CRITICAL)
// 6. High entropy in credential key context (SEC-HIGH-ENTROPY, HIGH)
func analyzeKeyValueInRoot(kv KeyValue, projectRoot string) []scanner.Finding {
	// Basic placeholder filter applies to all checks.
	if isBasicPlaceholder(kv.Value) {
		return nil
	}

	// SQL query strings are never secrets -- exclude before all detection methods.
	// Placed after isBasicPlaceholder (short strings already filtered) but before
	// prefix/connstring/credential checks. Even credential-named keys with SQL values
	// are safe (e.g., password: "SELECT 1" in test configs).
	if isSQLQuery(kv.Value) {
		return nil
	}

	var findings []scanner.Finding

	// 1. Check known prefixes (high confidence -- skip substring placeholder filter).
	for _, sp := range knownSecretPrefixes {
		if strings.HasPrefix(kv.Value, sp.Prefix) && len(kv.Value) >= sp.MinLen {
			findings = append(findings, scanner.Finding{
				RuleID:        "SEC-PREFIX",
				Severity:      scanner.SeverityCritical,
				RequirementID: "8.6.2",
				FilePath:      kv.FilePath,
				Line:          kv.Line,
				Description:   fmt.Sprintf("Possible %s detected in key %q", sp.Name, kv.Key),
				Suggestion:    "Remove hardcoded secret. Use a vault or environment variable injection.",
			})
			break // One prefix match is enough.
		}
	}

	// 2. Check connection strings (high confidence -- skip substring placeholder filter).
	for _, pat := range connStringPatterns {
		if pat.MatchString(kv.Value) {
			findings = append(findings, scanner.Finding{
				RuleID:        "SEC-CONNSTR",
				Severity:      scanner.SeverityCritical,
				RequirementID: "8.6.2",
				FilePath:      kv.FilePath,
				Line:          kv.Line,
				Description:   fmt.Sprintf("Connection string with embedded credentials in key %q", kv.Key),
				Suggestion:    "Remove credentials from connection string. Use separate credential injection.",
			})
			break // One match is enough.
		}
	}

	// For lower-confidence checks, also apply substring placeholder filter.
	if isSubstringPlaceholder(kv.Value) {
		return findings
	}

	// URL/path value discrimination. Keys ending in *_PATH
	// *_DIR, *_FILE, *_LOCATION, *_URL, *_URI, *_ENDPOINT, *_HOST whose values
	// look like paths or URLs are NOT credentials -- skip the lower-confidence
	// credential-name and entropy checks. SEC-PREFIX and SEC-CONNSTR already
	// ran above, so a real secret hidden behind a *_URL key is still caught
	// by the high-confidence branches.
	if hasPathOrURLKeySuffix(kv.Key) && isPathOrURLValue(kv.Value) {
		// Apply dev-context adjustment to any findings we've already collected
		// (prefix/connstr) and return without running credential-name checks.
		for i := range findings {
			dc := scanner.ClassifyDevContextInRoot(kv.FilePath, kv.Value, findings[i].Severity, projectRoot)
			findings[i].Severity = dc.AdjustedSev
			if dc.DedicatedDev && !dc.IsProdPath {
				findings[i].Severity = scanner.SeverityInfo
			}
			if dc.DedicatedDev || dc.IsDevPath || dc.IsPlaceholder {
				findings[i].DevContext = true
			}
			if dc.Label != "" {
				findings[i].Description = findings[i].Description + " [" + dc.Label + "]"
			}
		}
		return findings
	}

	// 3. Check credential key names.
	if isCredentialKey(kv.Key) {
		findings = append(findings, scanner.Finding{
			RuleID:        "SEC-CREDENTIAL-KEY",
			Severity:      scanner.SeverityCritical,
			RequirementID: "8.6.2",
			FilePath:      kv.FilePath,
			Line:          kv.Line,
			Description:   fmt.Sprintf("Hardcoded credential value in key %q", kv.Key),
			Suggestion:    "Remove hardcoded credential. Use a vault or environment variable injection.",
		})
	}

	// 4. Check high entropy in credential key context.
	if isCredentialKey(kv.Key) && isHighEntropy(kv.Value) {
		findings = append(findings, scanner.Finding{
			RuleID:        "SEC-HIGH-ENTROPY",
			Severity:      scanner.SeverityHigh,
			RequirementID: "8.6.2",
			FilePath:      kv.FilePath,
			Line:          kv.Line,
			Description:   fmt.Sprintf("High-entropy value in credential key %q (possible secret)", kv.Key),
			Suggestion:    "Verify this is not a hardcoded secret. Use a vault or environment variable injection.",
		})
	}

	// Apply dev-context severity adjustment to each finding (to).
	// Prod paths override to CRITICAL. Dev paths downgrade to MEDIUM.
	// Placeholders downgrade to MEDIUM. Dev+placeholder downgrades to INFO.
	// Dedicated-dev paths downgrade FURTHER to INFO.
	// All downgraded findings carry [dev-context] label for visibility.
	for i := range findings {
		dc := scanner.ClassifyDevContextInRoot(kv.FilePath, kv.Value, findings[i].Severity, projectRoot)
		findings[i].Severity = dc.AdjustedSev
		// dedicated-dev directories downgrade one additional
		// tier to Info. Guarded by !dc.IsProdPath so an attacker hiding
		// prod secrets behind a dev/ segment cannot bypass prod override.
		if dc.DedicatedDev && !dc.IsProdPath {
			findings[i].Severity = scanner.SeverityInfo
		}
		if dc.DedicatedDev || dc.IsDevPath || dc.IsPlaceholder {
			findings[i].DevContext = true
		}
		if dc.Label != "" {
			findings[i].Description = findings[i].Description + " [" + dc.Label + "]"
		}
	}

	return findings
}
