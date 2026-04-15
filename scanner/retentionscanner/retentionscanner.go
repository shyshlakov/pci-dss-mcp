// Package retentionscanner detects unsafe data retention patterns that violate
// PCI DSS 3.2.1 and 3.3.1: Redis/DB storage of sensitive authentication data
// without TTL, config files missing TTL on sensitive keys, and incorrect memory
// zeroing timing after authorization.
//
// Detection rules:
// - RET-REDIS-NO-TTL: Redis Set/SetNX with TTL=0 on sensitive data (3.2.1)
// - RET-REDIS-KEEP-TTL: Redis Set with KeepTTL on sensitive data (3.2.1)
// - RET-REDIS-NO-EXPIRE: Redis HSet without Expire on sensitive data (3.2.1)
// - RET-DB-SENSITIVE-STORE: SQL INSERT of sensitive data (3.2.1)
// - RET-GORM-SENSITIVE-STORE: gorm Create/Save of sensitive data (3.2.1)
// - RET-CONFIG-NO-TTL: Config key with sensitive name missing TTL sibling (3.2.1, 3.3.1)
// - RET-ZERO-BEFORE-AUTH: SAD zeroed before authorization call (3.2.1)
// - RET-ZERO-DEFER-ONLY: SAD zeroed only via defer (3.2.1)
// - RET-ZERO-AFTER-RESPONSE: SAD zeroed after response write (3.2.1)
package retentionscanner

import (
	"context"
	"fmt"
	"go/ast"
	"path"
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

// RetentionScanner detects unsafe data retention patterns in Go source and
// config files.
type RetentionScanner struct{}

// New creates a new RetentionScanner instance.
func New() *RetentionScanner {
	return &RetentionScanner{}
}

// Name implements scanner.Scanner.
func (s *RetentionScanner) Name() string {
	return "data_retention"
}

// Description implements scanner.Scanner.
func (s *RetentionScanner) Description() string {
	return "Detect unsafe data retention: Redis/DB without TTL, config missing TTL, memory zeroing timing (PCI DSS 3.2.1, 3.3.1)"
}

// Requirements implements scanner.Scanner.
func (s *RetentionScanner) Requirements() []string {
	return []string{"3.2.1", "3.3.1"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *RetentionScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
// It walks both.go and config files (.yaml,.yml,.json,.toml).
func (s *RetentionScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *RetentionScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	cfg := scanner.WalkConfig{
		Extensions:   []string{".go", ".yaml", ".yml", ".json", ".toml"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}

	walker := scanner.GitTrackedFiles
	if includeUntracked {
		walker = scanner.WalkFiles
	}
	for filePath, err := range walker(targetPath, cfg) {
		// Check for context cancellation between files.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err != nil {
			return nil, fmt.Errorf("walking files: %w", err)
		}

		ext := strings.ToLower(filepath.Ext(filePath))

		switch ext {
		case ".go":
			findings, lines, scanErr := s.scanGoFile(filePath)
			if scanErr != nil {
				return nil, fmt.Errorf("scanning %s: %w", filePath, scanErr)
			}
			result.Findings = append(result.Findings, findings...)
			result.Metadata.ScannedFiles++
			result.Metadata.ScannedLines += lines

		case ".yaml", ".yml", ".json", ".toml":
			findings, lines, scanErr := detectConfigMissingTTL(filePath)
			if scanErr != nil {
				return nil, fmt.Errorf("scanning config %s: %w", filePath, scanErr)
			}
			result.Findings = append(result.Findings, findings...)
			result.Metadata.ScannedFiles++
			result.Metadata.ScannedLines += lines
		}
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// scanGoFile parses a Go source file and runs all retention detection rules.
func (s *RetentionScanner) scanGoFile(filePath string) ([]scanner.Finding, int, error) {
	file, fset, err := scanner.ParseGoFile(filePath)
	if err != nil {
		return nil, 0, err
	}

	// Skip generated files.
	if ast.IsGenerated(file) {
		return nil, 0, nil
	}

	lineCount := fset.Position(file.End()).Line
	aliases := resolveImportAliases(file)

	var findings []scanner.Finding

	// 1. Redis TTL detection.
	findings = append(findings, detectRedisWithoutTTL(file, fset, filePath, aliases)...)

	// 2. DB/gorm persistent storage detection.
	findings = append(findings, detectDBStorageOfSensitiveData(file, fset, filePath, aliases)...)

	// 3. Memory zeroing timing detection.
	findings = append(findings, detectZeroingTimingIssues(file, fset, filePath)...)

	return findings, lineCount, nil
}

// resolveImportAliases builds a map from import path to local alias name.
func resolveImportAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			aliases[importPath] = imp.Name.Name
		} else {
			aliases[importPath] = path.Base(importPath)
		}
	}
	return aliases
}
