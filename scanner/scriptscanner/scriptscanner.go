// Package scriptscanner detects CSP header violations in Go payment handlers
// and SRI/nonce violations in HTML templates as required by PCI DSS 6.4.3 and
// 11.6.1.
//
// Detection rules (Go AST):
// - CSP-MISSING: Payment handler with no CSP header (6.4.3)
// - CSP-UNSAFE-INLINE: CSP with unsafe-inline (6.4.3)
// - CSP-UNSAFE-EVAL: CSP with unsafe-eval (6.4.3)
// - CSP-NO-SCRIPT-SRC: CSP without script-src or default-src (6.4.3)
// - CSP-VALUE-UNANALYZABLE: CSP set but value not a string literal (6.4.3)
// - CSP-OK: Valid CSP present (6.4.3)
package scriptscanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// defaultExcludePatterns are excluded by default from scanning.
var defaultExcludePatterns = []string{
	"vendor/",
	"generated/",
	"*.pb.go",
	"testdata/",
	"mocks/",
}

// ScriptScanner detects CSP header violations in Go payment handlers and
// SRI/nonce violations in HTML templates.
type ScriptScanner struct{}

// New creates a new ScriptScanner instance.
func New() *ScriptScanner {
	return &ScriptScanner{}
}

// Name implements scanner.Scanner.
func (s *ScriptScanner) Name() string {
	return "payment_page_scripts"
}

// Description implements scanner.Scanner.
func (s *ScriptScanner) Description() string {
	return "Detect CSP header violations in Go payment handlers and SRI/nonce violations in HTML templates (PCI DSS 6.4.3, 11.6.1)"
}

// Requirements implements scanner.Scanner.
func (s *ScriptScanner) Requirements() []string {
	return []string{"6.4.3", "11.6.1"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *ScriptScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *ScriptScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *ScriptScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	walker := scanner.GitTrackedFiles
	if includeUntracked {
		walker = scanner.WalkFiles
	}

	// Walk Go files for CSP header detection.
	goCfg := scanner.WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}

	for path, err := range walker(targetPath, goCfg) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err != nil {
			return nil, fmt.Errorf("walking files: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".go" {
			continue
		}

		findings, lines, scanErr := s.scanGoFile(path)
		if scanErr != nil {
			return nil, fmt.Errorf("scanning %s: %w", path, scanErr)
		}
		result.Findings = append(result.Findings, findings...)
		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines
	}

	// Walk HTML files for script tag analysis (implements scanHTMLFile).
	htmlCfg := scanner.WalkConfig{
		Extensions:   []string{".html", ".tmpl", ".gohtml", ".tpl", ".htm", ".gotmpl"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}

	for path, err := range walker(targetPath, htmlCfg) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err != nil {
			return nil, fmt.Errorf("walking HTML files: %w", err)
		}

		findings, lines, scanErr := s.scanHTMLFile(path)
		if scanErr != nil {
			return nil, fmt.Errorf("scanning %s: %w", path, scanErr)
		}
		result.Findings = append(result.Findings, findings...)
		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// scanHTMLFile is implemented in htmlcheck.go using golang.org/x/net/html
// tokenizer for SRI/nonce/CSP violation detection in HTML templates.
