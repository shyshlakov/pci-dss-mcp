// Package authscanner implements the authentication strength scanner that
// detects weak authentication patterns in Go source files: hardcoded passwords,
// weak password policies, and missing MFA middleware on payment routes.
//
// Detection rules:
// - AUTH-HARDCODED-PWD: Hardcoded passwords in var, const,:=, os.Setenv (PCI DSS 8.3.1)
// - AUTH-WEAK-POLICY: Password length checks below 12 characters (PCI DSS 8.3.6)
// - AUTH-BYTE-COUNT: Password length using len() instead of rune counting (PCI DSS 8.3.6)
// - AUTH-MISSING-MFA: Payment routes/handlers missing MFA middleware (PCI DSS 8.4.2)
package authscanner

import (
	"context"
	"fmt"
	"go/ast"
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

// AuthScanner detects weak authentication patterns in Go source files.
type AuthScanner struct{}

// New creates a new AuthScanner instance.
func New() *AuthScanner {
	return &AuthScanner{}
}

// Name implements scanner.Scanner.
func (s *AuthScanner) Name() string {
	return "auth_strength"
}

// Description implements scanner.Scanner.
func (s *AuthScanner) Description() string {
	return "Detect weak authentication patterns: hardcoded passwords, weak password policies, missing MFA on payment routes (PCI DSS 8.3.1, 8.3.6, 8.4.2)"
}

// Requirements implements scanner.Scanner.
func (s *AuthScanner) Requirements() []string {
	return []string{"8.3.1", "8.3.6", "8.4.2"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *AuthScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *AuthScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *AuthScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()

	// Absolutize the scan root so devcontext segment matching can reliably	// dependency.md Bug 2.
	if absRoot, absErr := filepath.Abs(targetPath); absErr == nil {
		targetPath = absRoot
	}

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	cfg := scanner.WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}

	walker := scanner.GitTrackedFiles
	if includeUntracked {
		walker = scanner.WalkFiles
	}
	for path, err := range walker(targetPath, cfg) {
		// Check for context cancellation between files.
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

		findings, lines, scanErr := s.scanGoFileInRoot(path, targetPath)
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

// scanGoFileInRoot parses a Go source file and applies all auth detection
// rules, plumbing the scan root through so detectHardcodedPasswordsInRoot
// can forward it to ClassifyDevContextInRoot.
func (s *AuthScanner) scanGoFileInRoot(path, projectRoot string) ([]scanner.Finding, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		return nil, 0, err
	}

	// Skip generated files.
	if ast.IsGenerated(file) {
		return nil, 0, nil
	}

	lineCount := fset.Position(file.End()).Line

	var findings []scanner.Finding

	// 1. Check hardcoded passwords.
	findings = append(findings, detectHardcodedPasswordsInRoot(file, fset, path, projectRoot)...)

	// 2. Check weak password policy.
	findings = append(findings, detectWeakPasswordPolicy(file, fset, path)...)

	// 3. Check missing MFA on payment routes/handlers.
	findings = append(findings, detectMissingMFA(file, fset, path)...)

	findings = ApplyS2SDowngrade(findings, file, fset, path)

	return findings, lineCount, nil
}
