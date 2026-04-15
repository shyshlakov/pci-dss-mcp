// Package cryptoscanner implements the encryption scanner that detects weak
// hash algorithms, hardcoded encryption keys/IVs, and plain HTTP URLs in Go
// source files.
//
// Detection rules:
// - CRYPTO-WEAK-HASH: Weak hash algorithms (md5/sha1) with context scoring
// - CRYPTO-HARDCODED-KEY: Three-tier hardcoded key/IV detection
// - CRYPTO-PLAIN-HTTP: Plain HTTP URL detection with localhost exclusion
//
// This scanner is scoped to application-level crypto only -- TLS transport
// configuration is NOT flagged (covered by a separate TLS scanner).
package cryptoscanner

import (
	"context"
	"fmt"
	"go/ast"
	"path/filepath"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// defaultExcludePatterns are excluded by default.
var defaultExcludePatterns = []string{
	"vendor/",
	"generated/",
	"*.pb.go",
	"testdata/",
	"mocks/",
}

// cryptoImportPaths are the import paths we resolve aliases for.
var cryptoImportPaths = []string{
	"crypto/md5",
	"crypto/sha1",
	"crypto/sha256",
	"crypto/des",
}

// EncryptionScanner detects encryption-related PCI DSS violations in Go source files.
type EncryptionScanner struct{}

// New creates a new EncryptionScanner instance.
func New() *EncryptionScanner {
	return &EncryptionScanner{}
}

// Name implements scanner.Scanner.
func (s *EncryptionScanner) Name() string {
	return "encryption"
}

// Description implements scanner.Scanner.
func (s *EncryptionScanner) Description() string {
	return "Detect weak hash algorithms, hardcoded encryption keys/IVs, and plain HTTP URLs in Go source files"
}

// Requirements implements scanner.Scanner.
func (s *EncryptionScanner) Requirements() []string {
	return []string{"6.2.4", "4.2.1"}
}

// Scan implements scanner.Scanner. Walks the target path for.go files and
// applies all encryption detection rules. Uses default exclude patterns.
func (s *EncryptionScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *EncryptionScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *EncryptionScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
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

		findings, lines, scanErr := scanGoFileInRoot(path, targetPath)
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

// scanGoFileInRoot parses a Go source file and applies all encryption
// detection rules, plumbing the scan root through so checkHardcodedKeys
// can forward it to ClassifyDevContextInRoot.
func scanGoFileInRoot(path, projectRoot string) ([]scanner.Finding, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		return nil, 0, err
	}

	// Skip generated files.
	if ast.IsGenerated(file) {
		return nil, 0, nil
	}

	lineCount := fset.Position(file.End()).Line

	// Resolve import aliases for crypto packages.
	importAliases := resolveImportAliases(file)

	var findings []scanner.Finding

	// 1. Check weak crypto usage with context scoring.
	findings = append(findings, checkWeakCrypto(file, fset, path, importAliases)...)

	// 2. Check hardcoded keys/IVs.
	findings = append(findings, checkHardcodedKeysInRoot(file, fset, path, projectRoot)...)

	// 3. Check plain HTTP URLs.
	findings = append(findings, checkPlainHTTP(file, fset, path)...)

	return findings, lineCount, nil
}

// resolveImportAliases builds a map of import path to local alias name for
// crypto-related packages. If no alias is specified, uses the last element
// of the import path (e.g., "crypto/md5" -> "md5").
func resolveImportAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string)
	for _, imp := range file.Imports {
		importPath := strings.Trim(imp.Path.Value, `"`)
		for _, target := range cryptoImportPaths {
			if importPath == target {
				if imp.Name != nil {
					// Explicit alias: import h "crypto/md5"
					aliases[target] = imp.Name.Name
				} else {
					// Default alias: last path element.
					parts := strings.Split(target, "/")
					aliases[target] = parts[len(parts)-1]
				}
				break
			}
		}
	}
	return aliases
}
