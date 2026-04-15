package suppression

import (
	"bufio"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// IgnoreRule represents a single rule from a.pci-dss-mcp-ignore file.
type IgnoreRule struct {
	Pattern    string // file path or glob, e.g., "config/test.json", "testdata/**"
	Line       int    // specific line number (0 = all lines in matched files)
	SourceLine int    // line number in .pci-dss-mcp-ignore file (for audit trail)
}

// ExcludePackageRule is a glob pattern that, when matched, causes scanner
// findings to be dropped before they reach the compliance report. Used for
// the `exclude-package:` directive. The recall-bias philosophy
// deliberately accepts FPs on non-payment code in exchange for zero
// silent skips — this directive is the
// ergonomic escape hatch for users hitting systematic context mismatches.
type ExcludePackageRule struct {
	Pattern    string // glob, e.g., "internal/card/**"
	SourceLine int    // line number in .pci-dss-mcp-ignore file (for audit trail)
}

// ParsedIgnoreFile bundles every directive class parsed from a single
// .pci-dss-mcp-ignore file. Returned by ParseIgnoreFileFull so callers can
// access both legacy IgnoreRule entries and ExcludePackageRule
// entries without breaking the original ParseIgnoreFile signature.
type ParsedIgnoreFile struct {
	Rules           []IgnoreRule
	ExcludePackages []ExcludePackageRule
}

// ParseIgnoreFile reads and parses a.pci-dss-mcp-ignore file. Returns nil, nil if
// the file does not exist — a missing ignore file is valid (no rules).
//
// Backwards-compatible thin wrapper around ParseIgnoreFileFull. Callers that
// need the new exclude-package directive should use ParseIgnoreFileFull.
func ParseIgnoreFile(path string) ([]IgnoreRule, error) {
	parsed, err := ParseIgnoreFileFull(path)
	if err != nil {
		return nil, err
	}
	if parsed == nil {
		return nil, nil
	}
	return parsed.Rules, nil
}

// ParseIgnoreFileFull reads and parses a.pci-dss-mcp-ignore file into all known
// directive classes. Returns nil, nil if the file does not exist.
func ParseIgnoreFileFull(path string) (*ParsedIgnoreFile, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close ignore file", "path", path, "err", cerr)
		}
	}()

	var rules []IgnoreRule
	var excludePkgs []ExcludePackageRule
	lineNum := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		lineNum++
		line := strings.TrimSpace(s.Text())

		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// exclude-package: <glob>
		if strings.HasPrefix(line, "exclude-package:") {
			pattern := strings.TrimSpace(strings.TrimPrefix(line, "exclude-package:"))
			if pattern == "" {
				continue
			}
			excludePkgs = append(excludePkgs, ExcludePackageRule{
				Pattern:    pattern,
				SourceLine: lineNum,
			})
			continue
		}

		rule := IgnoreRule{SourceLine: lineNum}

		// Check for colon separator: file:* or file:N
		lastColon := strings.LastIndex(line, ":")
		if lastColon > 0 {
			suffix := line[lastColon+1:]
			prefix := line[:lastColon]

			if suffix == "*" {
				// file:* — suppress all lines in file.
				rule.Pattern = prefix
				rule.Line = 0
				rules = append(rules, rule)
				continue
			}

			if n, err := strconv.Atoi(suffix); err == nil && n > 0 {
				// file:N — suppress specific line.
				rule.Pattern = prefix
				rule.Line = n
				rules = append(rules, rule)
				continue
			}
		}

		// No valid colon suffix — treat entire line as glob pattern.
		rule.Pattern = line
		rule.Line = 0
		rules = append(rules, rule)
	}

	if err := s.Err(); err != nil {
		return nil, err
	}
	return &ParsedIgnoreFile{Rules: rules, ExcludePackages: excludePkgs}, nil
}

// MatchesRule checks if a file path and line number match a single ignore rule.
func MatchesRule(rule IgnoreRule, filePath string, line int) bool {
	if !matchPattern(rule.Pattern, filePath) {
		return false
	}
	// Line 0 means match all lines.
	if rule.Line > 0 && rule.Line != line {
		return false
	}
	return true
}

// matchesAnyRule returns the first matching rule for a file path and line.
func matchesAnyRule(rules []IgnoreRule, filePath string, line int) (bool, IgnoreRule) {
	for _, rule := range rules {
		if MatchesRule(rule, filePath, line) {
			return true, rule
		}
	}
	return false, IgnoreRule{}
}

// matchPattern matches a file path against a pattern, supporting ** globs.
func matchPattern(pattern, filePath string) bool {
	if strings.Contains(pattern, "**") {
		return matchDoubleStar(pattern, filePath)
	}
	matched, _ := filepath.Match(pattern, filePath)
	return matched
}

// matchDoubleStar implements double-star glob matching.
// "testdata/**" matches any path starting with "testdata/".
// "**/*.go" matches any.go file at any depth.
func matchDoubleStar(pattern, filePath string) bool {
	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	// Check prefix.
	if prefix != "" && !strings.HasPrefix(filePath, prefix) {
		return false
	}

	// Check suffix.
	if suffix == "" || suffix == "/" {
		return true
	}

	// For suffix like "/*.go", check the remaining path after prefix.
	remaining := filePath
	if prefix != "" {
		remaining = filePath[len(prefix):]
	}

	// Try matching suffix against every possible subpath.
	// For "**/*.go" with file "a/b/c.go": try "/*.go" against "/b/c.go", "/c.go", etc.
	for i := 0; i < len(remaining); i++ {
		if remaining[i] == '/' || i == 0 {
			sub := remaining[i:]
			if matched, _ := filepath.Match(suffix[1:], filepath.Base(sub)); matched {
				return true
			}
		}
	}

	return false
}
