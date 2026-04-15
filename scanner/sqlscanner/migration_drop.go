package sqlscanner

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

var migrationFilenameRE = regexp.MustCompile(`^([0-9]{3,})_.*\.sql$`)

func isMigrationDir(dir string) bool {
	lower := strings.ToLower(filepath.ToSlash(dir))
	return strings.Contains(lower, "/migrations/") ||
		strings.Contains(lower, "/migration/") ||
		strings.HasSuffix(lower, "/migrations") ||
		strings.HasSuffix(lower, "/migration")
}

type migrationFile struct {
	ts   string
	name string
	path string
}

func listOrderedMigrationFiles(dir string) ([]migrationFile, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	var files []migrationFile
	var sawSQL bool
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".sql") {
			continue
		}
		sawSQL = true
		m := migrationFilenameRE.FindStringSubmatch(name)
		if m == nil {
			return nil, false
		}
		files = append(files, migrationFile{
			ts:   m[1],
			name: name,
			path: filepath.Join(dir, name),
		})
	}
	if !sawSQL || len(files) == 0 {
		return nil, false
	}
	sort.Slice(files, func(i, j int) bool { return files[i].ts < files[j].ts })
	return files, true
}

func dropColumnRegex(col string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(col)
	return regexp.MustCompile(`(?i)DROP\s+COLUMN\s+(IF\s+EXISTS\s+)?` + quoted + `(\s|;|,|$)`)
}

func addColumnRegex(col string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(col)
	return regexp.MustCompile(`(?i)ADD\s+COLUMN\s+(IF\s+NOT\s+EXISTS\s+)?` + quoted + `\b`)
}

func addColumnAlterRegex(col string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(col)
	return regexp.MustCompile(`(?i)ALTER\s+TABLE[^;]*ADD\s+[^;]*\b` + quoted + `\b`)
}

// applyMigrationDropDowngrade scans SQL findings in [sqlStart, sqlEnd) and
// downgrades SQL-SENSITIVE-COLUMN and SQL-TEXT-TYPE findings to INFO when a
// chronologically later migration file in the same directory drops the
// flagged column and no subsequent file re-adds it. metaIdx advancement
// mirrors crossRefSQLWithGoEncryption byte-for-byte: the loop condition
// includes `metaIdx < len(sqlMetas)` and the meta is read + advanced
// unconditionally at the top of each iteration.
func applyMigrationDropDowngrade(
	findings []scanner.Finding,
	sqlMetas []sqlFindingMeta,
	sqlStart, sqlEnd int,
) []scanner.Finding {
	if sqlStart >= sqlEnd || sqlStart < 0 || sqlEnd > len(findings) {
		return findings
	}
	if len(sqlMetas) == 0 {
		return findings
	}

	cache := map[string][]migrationFile{}
	body := map[string]string{}

	readBody := func(path string) string {
		if b, ok := body[path]; ok {
			return b
		}
		data, err := os.ReadFile(path)
		if err != nil {
			body[path] = ""
			return ""
		}
		body[path] = string(data)
		return body[path]
	}

	metaIdx := 0
	for i := sqlStart; i < sqlEnd && metaIdx < len(sqlMetas); i++ {
		f := &findings[i]
		meta := sqlMetas[metaIdx]
		metaIdx++

		if f.RuleID != RuleSQLSensitiveColumn && f.RuleID != RuleSQLTextType {
			continue
		}
		if f.Severity == scanner.SeverityInfo {
			continue
		}

		dir := filepath.Dir(f.FilePath)
		if !isMigrationDir(dir) {
			continue
		}

		ordered, seen := cache[dir]
		if !seen {
			var ok bool
			ordered, ok = listOrderedMigrationFiles(dir)
			if !ok {
				cache[dir] = nil
				continue
			}
			cache[dir] = ordered
		} else if ordered == nil {
			continue
		}

		baseSelf := filepath.Base(f.FilePath)
		selfIdx := -1
		for idx, mf := range ordered {
			if mf.name == baseSelf {
				selfIdx = idx
				break
			}
		}
		if selfIdx == -1 || selfIdx == len(ordered)-1 {
			continue
		}

		dropRE := dropColumnRegex(meta.ColumnName)
		addRE := addColumnRegex(meta.ColumnName)
		addAlterRE := addColumnAlterRegex(meta.ColumnName)

		dropAtIdx := -1
		for idx := selfIdx + 1; idx < len(ordered); idx++ {
			src := readBody(ordered[idx].path)
			if src == "" {
				continue
			}
			if dropRE.MatchString(src) {
				dropAtIdx = idx
				break
			}
		}
		if dropAtIdx == -1 {
			continue
		}

		reAdded := false
		for idx := dropAtIdx + 1; idx < len(ordered); idx++ {
			src := readBody(ordered[idx].path)
			if src == "" {
				continue
			}
			if addRE.MatchString(src) || addAlterRE.MatchString(src) {
				reAdded = true
				break
			}
		}
		if reAdded {
			continue
		}

		dropNameNoExt := strings.TrimSuffix(ordered[dropAtIdx].name, filepath.Ext(ordered[dropAtIdx].name))
		f.Severity = scanner.SeverityInfo
		f.Confidence = "high"
		f.TriageHint = "downgrade:column_dropped_in_" + dropNameNoExt +
			" | Column dropped in later migration " + ordered[dropAtIdx].name + " and not re-added."
	}
	return findings
}
