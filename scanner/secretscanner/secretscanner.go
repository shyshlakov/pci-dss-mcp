package secretscanner

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
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

// SecretsScanner detects hardcoded secrets in configuration files
// (.env,.yaml,.json,.toml) using prefix matching, credential key
// detection, entropy analysis, and connection string pattern matching.
type SecretsScanner struct{}

// New creates a new SecretsScanner instance.
func New() *SecretsScanner {
	return &SecretsScanner{}
}

// Name implements scanner.Scanner.
func (s *SecretsScanner) Name() string {
	return "secrets"
}

// Description implements scanner.Scanner.
func (s *SecretsScanner) Description() string {
	return "Detect hardcoded secrets in config files (.env, .yaml, .json, .toml) -- PCI DSS 8.6.2"
}

// Requirements implements scanner.Scanner.
func (s *SecretsScanner) Requirements() []string {
	return []string{"8.6.2"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *SecretsScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
// For each config file found, it dispatches to the appropriate parser,
// then feeds all KeyValue results through the detection engine.
func (s *SecretsScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *SecretsScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()

	// Absolutize the scan root so devcontext segment matching can reliably	// dependency.md Bug 2.
	if absRoot, absErr := filepath.Abs(targetPath); absErr == nil {
		targetPath = absRoot
	}

	result := &scanner.ScanResult{
		Findings: []scanner.Finding{},
	}

	cfg := scanner.WalkConfig{
		Extensions:   []string{".env", ".yaml", ".yml", ".json", ".toml"},
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

		kvs, lines, parseErr := ParseConfigFile(path)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, parseErr)
		}

		for _, kv := range kvs {
			findings := analyzeKeyValueInRoot(kv, targetPath)
			result.Findings = append(result.Findings, findings...)
		}

		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// ParseConfigFile dispatches to the correct parser based on file extension.
// Returns parsed KeyValue tuples, approximate line count, and error.
func ParseConfigFile(path string) ([]KeyValue, int, error) {
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".env":
		kvs, err := ParseEnvFile(path)
		if err != nil {
			return nil, 0, err
		}
		lines, _ := countLines(path)
		return kvs, lines, nil

	case ".yaml", ".yml":
		kvs, err := ParseYAMLFile(path)
		if err != nil {
			return nil, 0, err
		}
		lines, _ := countLines(path)
		return kvs, lines, nil

	case ".json":
		kvs, err := ParseJSONFile(path)
		if err != nil {
			return nil, 0, err
		}
		lines, _ := countLines(path)
		return kvs, lines, nil

	case ".toml":
		kvs, err := ParseTOMLFile(path)
		if err != nil {
			return nil, 0, err
		}
		lines, _ := countLines(path)
		return kvs, lines, nil

	default:
		return nil, 0, nil
	}
}

// countLines counts the number of lines in a file.
func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close file while counting lines", "path", path, "err", cerr)
		}
	}()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		count++
	}
	return count, sc.Err()
}

// readFileBytes is a helper for tests.
func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// writeFileBytes is a helper for tests.
func writeFileBytes(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
