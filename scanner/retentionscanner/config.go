package retentionscanner

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/secretscanner"
)

// isSkippableFilename returns true if the file path indicates a non-application
// config file that should not be scanned for TTL settings (swagger specs,
// package manifests, example files, docs directories, etc.).
func isSkippableFilename(path string) bool {
	base := strings.ToLower(filepath.Base(path))

	// Exact basename matches for known non-application config files.
	skipBasenames := map[string]bool{
		"swagger.json": true, "swagger.yaml": true, "swagger.yml": true,
		"openapi.json": true, "openapi.yaml": true, "openapi.yml": true,
		"package.json": true, "package-lock.json": true,
		"tsconfig.json": true, "tsconfig.base.json": true,
		"composer.json": true,
	}
	if skipBasenames[base] {
		return true
	}

	// Basename contains indicator words for non-production configs.
	for _, word := range []string{"example", "sample", "fixture", "mock", "demo"} {
		if strings.Contains(base, word) {
			return true
		}
	}

	// Path segment matches (directory patterns).
	lowerPath := strings.ToLower(path)
	for _, seg := range []string{"/docs/", "/swagger/", "/openapi/", "/flagd/"} {
		if strings.Contains(lowerPath, seg) {
			return true
		}
	}

	return false
}

// isSchemaOrDocFile returns true if the parsed key-value pairs indicate a
// schema definition or API documentation file rather than application config.
// Checks the first segment of each dot-separated key path since the JSON parser
// flattens nested maps into dotted key paths (e.g. "definitions.Card.type").
func isSchemaOrDocFile(kvs []secretscanner.KeyValue) bool {
	schemaKeys := map[string]bool{
		"swagger": true, "openapi": true, "$schema": true,
		"definitions": true, "paths": true, "components": true,
		"info": true,
	}

	for _, kv := range kvs {
		first := firstSegment(kv.Key)
		if schemaKeys[strings.ToLower(first)] {
			return true
		}
	}
	return false
}

// isFeatureFlagConfig returns true if the parsed key-value pairs indicate a
// feature flag configuration file (flagd, LaunchDarkly-style, etc.).
// Requires at least 2 distinct indicator keys to reduce false positives.
// Checks all segments of each key path since the JSON parser flattens nested
// maps into dotted paths (e.g. "feature.card_data.variants.on").
func isFeatureFlagConfig(kvs []secretscanner.KeyValue) bool {
	flagIndicators := map[string]bool{
		"variants": true, "enabled": true, "percentage": true,
		"rollout": true, "defaultvariant": true, "targeting": true,
	}

	seen := make(map[string]bool)
	for _, kv := range kvs {
		segments := strings.Split(kv.Key, ".")
		for _, seg := range segments {
			lower := strings.ToLower(seg)
			if flagIndicators[lower] && !seen[lower] {
				seen[lower] = true
			}
		}
	}
	return len(seen) >= 2
}

// firstSegment returns the first dot-separated segment of a key path.
// "a.b.c" -> "a", "a" -> "a".
func firstSegment(key string) string {
	if idx := strings.Index(key, "."); idx >= 0 {
		return key[:idx]
	}
	return key
}

// sensitiveConfigKeys are substrings indicating a config key relates to
// sensitive/payment data. Matched case-insensitively against the last segment
// of dot-separated key paths.
var sensitiveConfigKeys = []string{
	"card",
	"pan",
	"cvv",
	"payment",
	"sensitive",
	"cardholder",
	"sad",
	"auth_data",
}

// ttlSiblingKeys are substrings indicating a TTL/expiry configuration.
// If a sensitive config key has a sibling whose name contains one of these,
// it is considered properly configured.
var ttlSiblingKeys = []string{
	"ttl",
	"expiry",
	"expiration",
	"retention",
	"max_age",
	"timeout",
}

// detectConfigMissingTTL parses a config file and checks if sensitive keys
// have TTL sibling keys in the same parent group.
func detectConfigMissingTTL(path string) ([]scanner.Finding, int, error) {
	// Fast path: skip files that are clearly not application configs.
	if isSkippableFilename(path) {
		return nil, 0, nil
	}

	kvs, lines, err := secretscanner.ParseConfigFile(path)
	if err != nil {
		return nil, 0, err
	}

	if len(kvs) == 0 {
		return nil, lines, nil
	}

	// Content fingerprinting: skip schema/doc files and feature flag configs.
	if isSchemaOrDocFile(kvs) {
		return nil, lines, nil
	}
	if isFeatureFlagConfig(kvs) {
		return nil, lines, nil
	}

	// Group keys by parent prefix.
	groups := groupByParent(kvs)

	var findings []scanner.Finding

	for parentKey, siblings := range groups {
		// Check if the parent key path contains a sensitive keyword.
		// This catches groups like "cvv_cache", "cardholder_data", "card_processing.card_data".
		if !isAnySensitiveSegment(parentKey) {
			continue
		}

		// Check if any sibling key in this group has a TTL-like name.
		hasTTL := false
		for _, sib := range siblings {
			sibName := lastSegment(sib.Key)
			if isTTLKey(sibName) {
				hasTTL = true
				break
			}
		}

		if !hasTTL {
			// Use the first sibling's line for the finding location.
			line := 0
			if len(siblings) > 0 {
				line = siblings[0].Line
			}
			desc := fmt.Sprintf(
				"Sensitive data config group %q missing TTL/expiry setting. "+
					"PCI DSS 3.2.1, 3.3.1 require data retention limits.",
				parentKey,
			)
			f := scanner.Finding{
				RuleID:        "RET-CONFIG-NO-TTL",
				Severity:      scanner.SeverityHigh,
				RequirementID: "3.2.1",
				FilePath:      path,
				Line:          line,
				Description:   desc,
				Suggestion:    "Add a TTL/expiry/retention setting alongside sensitive data configuration.",
			}
			if isDevConfigPath(path) {
				f.Severity = scanner.SeverityInfo
				f.Confidence = "high"
				f.TriageHint = "downgrade:dev_path_skipped | " + downgradeReasonDevPath
			}
			findings = append(findings, f)
		}
	}

	return findings, lines, nil
}

// groupByParent groups KeyValue tuples by their parent prefix (everything
// before the last "." in the key). Keys without a dot separator use the key
// itself as the parent.
func groupByParent(kvs []secretscanner.KeyValue) map[string][]secretscanner.KeyValue {
	groups := make(map[string][]secretscanner.KeyValue)
	for _, kv := range kvs {
		parent := parentKey(kv.Key)
		groups[parent] = append(groups[parent], kv)
	}
	return groups
}

// parentKey returns the parent portion of a dot-separated key path.
// "a.b.c" -> "a.b", "a" -> "a".
func parentKey(key string) string {
	if idx := strings.LastIndex(key, "."); idx >= 0 {
		return key[:idx]
	}
	return key
}

// lastSegment returns the last dot-separated segment of a key path.
// "a.b.c" -> "c", "a" -> "a".
func lastSegment(key string) string {
	if idx := strings.LastIndex(key, "."); idx >= 0 {
		return key[idx+1:]
	}
	return key
}

// isAnySensitiveSegment checks if any dot-separated segment in a key path
// contains a sensitive keyword. This handles parent keys like "cvv_cache",
// "card_processing.card_data", "cardholder_data".
func isAnySensitiveSegment(keyPath string) bool {
	segments := strings.Split(keyPath, ".")
	for _, seg := range segments {
		if isSensitiveConfigKey(seg) {
			return true
		}
	}
	return false
}

// isSensitiveConfigKey checks if a key name contains any sensitive keyword
// (case-insensitive substring match).
func isSensitiveConfigKey(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range sensitiveConfigKeys {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isTTLKey checks if a key name contains any TTL/expiry keyword
// (case-insensitive substring match).
func isTTLKey(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range ttlSiblingKeys {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
