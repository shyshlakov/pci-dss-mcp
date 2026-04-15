package errorscanner

import (
	"context"
	"fmt"
	"go/ast"
	"path/filepath"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/internal/keywords"
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

// ErrorScanner detects payment handlers leaking internal error details to
// HTTP responses. It identifies four error leak patterns in functions that
// match payment-related naming conventions and have http.ResponseWriter
// parameters.
type ErrorScanner struct{}

// New creates a new ErrorScanner instance.
func New() *ErrorScanner {
	return &ErrorScanner{}
}

// Name implements scanner.Scanner.
func (s *ErrorScanner) Name() string {
	return "error_handling"
}

// Description implements scanner.Scanner.
func (s *ErrorScanner) Description() string {
	return "Detect payment handlers leaking internal error details to HTTP responses (PCI DSS 6.2.4)"
}

// Requirements implements scanner.Scanner.
func (s *ErrorScanner) Requirements() []string {
	return []string{"6.2.4"}
}

// Scan implements scanner.Scanner. Walks the target path for.go files and
// applies all error leak detection rules. Uses default exclude patterns.
func (s *ErrorScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
// For each.go file, it parses the AST, identifies payment handler functions
// (by name keyword + ResponseWriter param), and checks their bodies for
// error leak patterns.
func (s *ErrorScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *ErrorScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()

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

		findings, lines, scanErr := s.scanGoFile(path)
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

// scanGoFile parses a Go source file and checks payment handler functions for
// error leak patterns.
func (s *ErrorScanner) scanGoFile(path string) ([]scanner.Finding, int, error) {
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

	// per-PackageInfo score cache is fresh on each
	// construction -- no global reset required.
	pkgInfo := keywords.PackageInfoFromFile(file, fset, path)

	// Walk top-level function declarations.
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}

		// Multi-signal payment context gate.
		if !keywords.IsPaymentContext(fn, pkgInfo) {
			continue
		}
		if !HasResponseWriterParam(fn) {
			continue
		}

		// Check the function body for error leak patterns.
		leaks := DetectErrorLeaksInBody(fn.Body, fset, path)
		findings = append(findings, leaks...)
	}

	return findings, lineCount, nil
}
