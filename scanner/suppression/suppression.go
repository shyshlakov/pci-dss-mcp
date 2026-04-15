// Package suppression provides centralized suppression of scanner findings
// via inline pci-ignore comments and.pci-dss-mcp-ignore file rules.
package suppression

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// SuppressionResult wraps a finding with its suppression status and audit trail.
type SuppressionResult struct {
	Finding           scanner.Finding
	Suppressed        bool
	SuppressionReason string // reason text from comment or ".pci-dss-mcp-ignore"
	SuppressionSource string // "inline comment" or ".pci-dss-mcp-ignore:N"
}

// ExcludedPackageReport describes one exclude-package directive that matched
// at least one finding. The reportscanner uses these to emit
// SUPPRESSED-PACKAGE INFO entries for the QSA audit trail.
type ExcludedPackageReport struct {
	Pattern    string
	MatchCount int
	SourceLine int
}

// MatchExcludePackage reports whether filePath matches the given
// exclude-package glob. Exposed so reportscanner can filter parallel
// (findings, scannerName) slices in lockstep without re-implementing the
// glob semantics. The pattern uses the same ** double-star syntax as the
// legacy `rule:` directive matcher.
func MatchExcludePackage(pattern, filePath string) bool {
	if pattern == "" {
		return false
	}
	return matchPattern(pattern, filePath)
}

// ApplyPackageExclusions drops findings whose project-relative path matches
// any ExcludePackageRule. Returns the filtered findings plus one
// ExcludedPackageReport per pattern that matched at least one finding.
//
// The dropped findings are intentionally not surfaced as inline SUPPRESSED
// entries — package exclusion is a coarser, scope-level operation and the
// caller emits ONE SUPPRESSED-PACKAGE INFO finding per matched pattern instead
// (see reportscanner). This keeps the report compact on large excluded trees.
//
// Passing nil rules or empty findings is safe.
func ApplyPackageExclusions(findings []scanner.Finding, projectRoot string, rules []ExcludePackageRule) ([]scanner.Finding, []ExcludedPackageReport) {
	if len(rules) == 0 || len(findings) == 0 {
		return findings, nil
	}

	counts := make(map[string]int, len(rules))
	sources := make(map[string]int, len(rules))
	for _, r := range rules {
		sources[r.Pattern] = r.SourceLine
	}

	filtered := make([]scanner.Finding, 0, len(findings))
	for _, f := range findings {
		relPath := f.FilePath
		if filepath.IsAbs(f.FilePath) {
			if rel, err := filepath.Rel(projectRoot, f.FilePath); err == nil {
				relPath = rel
			}
		}
		excluded := false
		for _, r := range rules {
			if matchPattern(r.Pattern, relPath) {
				excluded = true
				counts[r.Pattern]++
				break
			}
		}
		if !excluded {
			filtered = append(filtered, f)
		}
	}

	var reports []ExcludedPackageReport
	for _, r := range rules {
		if counts[r.Pattern] > 0 {
			reports = append(reports, ExcludedPackageReport{
				Pattern:    r.Pattern,
				MatchCount: counts[r.Pattern],
				SourceLine: sources[r.Pattern],
			})
		}
	}
	return filtered, reports
}

// ApplySuppression checks each finding against.pci-dss-mcp-ignore rules and inline
// pci-ignore comments. Suppressed findings carry reason and source for audit trail.
func ApplySuppression(findings []scanner.Finding, projectRoot string) []SuppressionResult {
	results := make([]SuppressionResult, len(findings))

	// Parse.pci-dss-mcp-ignore file (missing file is valid — no rules).
	ignoreRules, _ := ParseIgnoreFile(filepath.Join(projectRoot, ".pci-dss-mcp-ignore"))

	// Cache file contents to avoid re-reading the same file.
	fileCache := make(map[string][]string)

	for i, f := range findings {
		results[i] = SuppressionResult{Finding: f}

		// Normalize path relative to projectRoot for ignore rule matching.
		relPath := f.FilePath
		if filepath.IsAbs(f.FilePath) {
			if rel, err := filepath.Rel(projectRoot, f.FilePath); err == nil {
				relPath = rel
			}
		}

		// Check.pci-dss-mcp-ignore rules first.
		if matched, rule := matchesAnyRule(ignoreRules, relPath, f.Line); matched {
			results[i].Suppressed = true
			results[i].SuppressionReason = "matched pattern: " + rule.Pattern
			results[i].SuppressionSource = formatIgnoreFileSource(rule.SourceLine)
			continue
		}

		// Check inline comment.
		line, err := cachedReadLine(fileCache, f.FilePath, f.Line)
		if err != nil {
			continue // file missing or line out of range — not suppressed
		}

		if reason, found := detectInlineSuppression(f.FilePath, line); found {
			results[i].Suppressed = true
			results[i].SuppressionReason = reason
			results[i].SuppressionSource = "inline comment"
		}
	}

	return results
}

// formatIgnoreFileSource returns the audit trail source string for an ignore file match.
func formatIgnoreFileSource(sourceLine int) string {
	return ".pci-dss-mcp-ignore:" + strconv.Itoa(sourceLine)
}

// detectInlineSuppression checks if a source line contains a pci-ignore comment
// appropriate for the file type. Returns the reason text and whether suppression was found.
func detectInlineSuppression(filePath string, lineContent string) (reason string, found bool) {
	ext := strings.ToLower(filepath.Ext(filePath))

	var prefixes []string
	switch ext {
	case ".go":
		prefixes = []string{"// pci-ignore:", "//pci-ignore:"}
	case ".yaml", ".yml", ".env", ".toml":
		prefixes = []string{"# pci-ignore:", "#pci-ignore:"}
	case ".html", ".tmpl", ".gohtml":
		prefixes = []string{"<!-- pci-ignore:", "<!--pci-ignore:"}
	default:
		return "", false
	}

	for _, prefix := range prefixes {
		idx := strings.Index(lineContent, prefix)
		if idx < 0 {
			continue
		}
		after := lineContent[idx+len(prefix):]
		// For HTML, trim trailing -->
		if ext == ".html" || ext == ".tmpl" || ext == ".gohtml" {
			after = strings.TrimSuffix(strings.TrimSpace(after), "-->")
		}
		return strings.TrimSpace(after), true
	}

	return "", false
}

// cachedReadLine reads a specific line from a file, using a cache to avoid re-reading.
func cachedReadLine(cache map[string][]string, path string, lineNum int) (string, error) {
	lines, ok := cache[path]
	if !ok {
		var err error
		lines, err = readFileLines(path)
		if err != nil {
			return "", err
		}
		cache[path] = lines
	}
	if lineNum < 1 || lineNum > len(lines) {
		return "", os.ErrNotExist
	}
	return lines[lineNum-1], nil
}

// readFileLines reads all lines of a file into a string slice.
func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close file while reading lines", "path", path, "err", cerr)
		}
	}()

	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, s.Err()
}
