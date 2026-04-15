package reportscanner

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type expectedContract struct {
	frontmatter expectedFrontmatter
	violations  []expectedFinding
	cleanFiles  []string
}

type expectedFrontmatter struct {
	FixtureVersion             string              `yaml:"fixture_version"`
	TotalIntentionalViolations int                 `yaml:"total_intentional_violations"`
	TotalCleanPatterns         int                 `yaml:"total_clean_patterns"`
	ExpectedSummary            map[string]int      `yaml:"expected_summary"`
	RulesCoverage              map[string][]string `yaml:"rules_coverage"`
}

type expectedFinding struct {
	RuleID   string
	Severity string
	FilePath string
	Line     int
	Notes    string
}

// copyFixtureTree recursively copies src into a fresh t.TempDir() and returns
// the destination path. Mandatory before scanning the golden fixture: scanner.
// DefaultExcludeDirs (scanner/walker.go:29) contains "testdata", so the walker
// skips any path segment named "testdata" and yields zero findings. Copying
// into t.TempDir() strips the "testdata" segment from the absolute scan path.
func copyFixtureTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("walk %s: %w", path, walkErr)
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("mkdir parent %s: %w", target, err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", target, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("copyFixtureTree(%s): %v", src, err)
	}
	return dst
}

func parseExpectedContract(path string) (*expectedContract, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open expected contract: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var (
		fmLines       []string
		bodyLines     []string
		inFrontmatter bool
		fmDone        bool
	)
	for sc.Scan() {
		line := sc.Text()
		if line == "---" {
			if !inFrontmatter && !fmDone {
				inFrontmatter = true
				continue
			}
			if inFrontmatter {
				inFrontmatter = false
				fmDone = true
				continue
			}
		}
		if inFrontmatter {
			fmLines = append(fmLines, line)
		} else if fmDone {
			bodyLines = append(bodyLines, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan contract: %w", err)
	}

	var fm expectedFrontmatter
	if err := yaml.Unmarshal([]byte(strings.Join(fmLines, "\n")), &fm); err != nil {
		return nil, fmt.Errorf("parse frontmatter yaml: %w", err)
	}

	violations, cleanFiles := parseBodyTables(bodyLines)
	return &expectedContract{
		frontmatter: fm,
		violations:  violations,
		cleanFiles:  cleanFiles,
	}, nil
}

func parseBodyTables(lines []string) ([]expectedFinding, []string) {
	var (
		violations []expectedFinding
		cleanFiles []string
		section    string
	)
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "## Violations") {
			section = "violations"
			continue
		}
		if strings.HasPrefix(line, "## Clean") {
			section = "clean"
			continue
		}
		if strings.HasPrefix(line, "##") {
			section = ""
			continue
		}
		if !strings.HasPrefix(line, "|") {
			continue
		}
		if strings.HasPrefix(line, "|---") || strings.HasPrefix(line, "|--") {
			continue
		}
		if strings.HasPrefix(line, "| Rule") || strings.HasPrefix(line, "| File") || strings.HasPrefix(line, "| Severity") {
			continue
		}
		cells := splitTableRow(line)
		switch section {
		case "violations":
			if len(cells) >= 4 {
				lineNum := 0
				_, _ = fmt.Sscanf(cells[3], "%d", &lineNum)
				notes := ""
				if len(cells) >= 5 {
					notes = cells[4]
				}
				violations = append(violations, expectedFinding{
					RuleID:   cells[0],
					Severity: cells[1],
					FilePath: cells[2],
					Line:     lineNum,
					Notes:    notes,
				})
			}
		case "clean":
			if len(cells) >= 1 && cells[0] != "" {
				cleanFiles = append(cleanFiles, cells[0])
			}
		}
	}
	return violations, cleanFiles
}

func splitTableRow(line string) []string {
	trimmed := strings.Trim(line, "|")
	parts := strings.Split(trimmed, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
