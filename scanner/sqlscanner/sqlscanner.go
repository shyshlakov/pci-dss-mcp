// Package sqlscanner detects sensitive cardholder columns in SQL migration
// files and Go gorm/db/sql struct tags that persist PAN/SAD without
// application-level encryption.
//
// Rules:
//
//	SQL-SENSITIVE-COLUMN (3.3.1, HIGH) — column name matches panscanner
//	 keywords in CREATE/ALTER TABLE
//	SQL-TEXT-TYPE (3.5.1, MEDIUM) — sensitive column declared as
//	 text/varchar/char/citext/string
//	GORM-SENSITIVE-TAG (3.3.1, HIGH) — Go struct field with sensitive
//	 gorm/db/sql tag (INFO when the
//	 struct has an encryption hook, )
//	GORM-NO-ENCRYPT-HOOK (3.5.1, HIGH) — struct has sensitive tag but no
//	 BeforeCreate/BeforeSave/BeforeUpdate
//	 /AfterFind method referencing
//	 Encrypt/Decrypt
package sqlscanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// Rule IDs exported for use in reportscanner tests and downstream tooling.
const (
	RuleSQLSensitiveColumn = "SQL-SENSITIVE-COLUMN"
	RuleSQLTextType        = "SQL-TEXT-TYPE"
	RuleGormSensitiveTag   = "GORM-SENSITIVE-TAG"
	RuleGormNoEncryptHook  = "GORM-NO-ENCRYPT-HOOK"
)

// defaultExcludePatterns are excluded from scanning by default. testdata/ is
// redundant with the walker's DefaultExcludeDirs but kept here for parity with
// other scanners (retentionscanner, auditscanner).
var defaultExcludePatterns = []string{
	"vendor/",
	"generated/",
	"*.pb.go",
	"testdata/",
	"mocks/",
}

// SQLScanner implements scanner.Scanner for SQL schema + gorm struct tag rules.
type SQLScanner struct{}

// New returns a ready-to-use SQLScanner.
func New() *SQLScanner { return &SQLScanner{} }

// Name implements scanner.Scanner.
func (s *SQLScanner) Name() string { return "sql_schema" }

// Description implements scanner.Scanner.
func (s *SQLScanner) Description() string {
	return "Detect sensitive cardholder columns in SQL migrations and gorm struct tags stored without application-level encryption (PCI DSS 3.3.1, 3.5.1)"
}

// Requirements implements scanner.Scanner.
func (s *SQLScanner) Requirements() []string {
	return []string{"3.3.1", "3.5.1"}
}

// Scan implements scanner.Scanner.
func (s *SQLScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *SQLScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// goEncryptInfo holds encryption metadata for a Go struct's table,
// collected during Pass 2 for SQL cross-reference in Pass 3.
type goEncryptInfo struct {
	TableName       string          // resolved effective table name
	EncryptedFields map[string]bool // Go field names with Encrypt hook
	HasEncryptHook  bool            // struct has any encrypt hook
	// columnToField maps lowercase gorm column name → Go field name,
	// so cross-ref can match SQL column names to Go encrypted fields.
	ColumnToField map[string]string
}

// sqlFindingMeta holds per-SQL-finding metadata for cross-reference.
type sqlFindingMeta struct {
	TableName  string
	ColumnName string
}

// ScanFull provides the full scan API consumed by reportscanner for
// include_tests / include_untracked toggles. It walks three passes over the
// target tree:.sql files,.go files, then cross-reference.
func (s *SQLScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	start := time.Now()
	result := &scanner.ScanResult{Findings: []scanner.Finding{}}

	walker := scanner.GitTrackedFiles
	if includeUntracked {
		walker = scanner.WalkFiles
	}

	// Pass 1:.sql files → CREATE / ALTER TABLE parsing.
	// Track per-finding metadata for cross-reference.
	sqlFindingStart := 0 // index into result.Findings where SQL findings begin
	var sqlMetas []sqlFindingMeta
	sqlCfg := scanner.WalkConfig{
		Extensions:   []string{".sql"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}
	for path, werr := range walker(targetPath, sqlCfg) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if werr != nil {
			return nil, fmt.Errorf("walking sql files: %w", werr)
		}
		if strings.ToLower(filepath.Ext(path)) != ".sql" {
			continue
		}
		findings, metas, lines, err := s.scanSQLFileWithMeta(path)
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", path, err)
		}
		result.Findings = append(result.Findings, findings...)
		sqlMetas = append(sqlMetas, metas...)
		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines
	}
	sqlFindingEnd := len(result.Findings)

	// Pass 2:.go files → gorm/db/sql tag + encryption hook analysis.
	// Also collect GormStruct data for cross-reference (, T-19-04).
	goEncryptByTable := map[string]goEncryptInfo{}
	goCfg := scanner.WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: excludePatterns,
		IncludeTests: includeTests,
	}
	for path, werr := range walker(targetPath, goCfg) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if werr != nil {
			return nil, fmt.Errorf("walking go files: %w", werr)
		}
		if strings.ToLower(filepath.Ext(path)) != ".go" {
			continue
		}
		findings, structs, lines, err := s.scanGoFileWithStructs(path)
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", path, err)
		}
		result.Findings = append(result.Findings, findings...)
		result.Metadata.ScannedFiles++
		result.Metadata.ScannedLines += lines

		// Collect encryption data for cross-reference.
		for _, gs := range structs {
			if gs.EffectiveTableName == "" {
				continue
			}
			key := strings.ToLower(gs.EffectiveTableName)
			goEncryptByTable[key] = goEncryptInfo{
				TableName:       gs.EffectiveTableName,
				EncryptedFields: gs.EncryptedFields,
				HasEncryptHook:  gs.HasEncryptHook,
				ColumnToField:   gs.ColumnToField,
			}
		}
	}

	// Pass 3: cross-reference SQL findings with Go encryption hooks.
	if len(goEncryptByTable) > 0 && len(sqlMetas) > 0 {
		result.Findings = crossRefSQLWithGoEncryption(
			result.Findings, sqlFindingStart, sqlFindingEnd,
			sqlMetas, goEncryptByTable,
		)
	}

	if sqlFindingEnd > sqlFindingStart && len(sqlMetas) > 0 {
		result.Findings = applyMigrationDropDowngrade(
			result.Findings, sqlMetas,
			sqlFindingStart, sqlFindingEnd,
		)
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// scanSQLFileWithMeta reads a .sql file, parses CREATE/ALTER TABLE statements,
// and emits SQL-SENSITIVE-COLUMN + SQL-TEXT-TYPE findings along with per-finding
// metadata (table name, column name) for cross-reference.
func (s *SQLScanner) scanSQLFileWithMeta(path string) ([]scanner.Finding, []sqlFindingMeta, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, 0, err
	}
	src := string(data)
	lineCount := strings.Count(src, "\n") + 1

	allCols := ParseSQLFile(src)

	// Group columns by table to determine panProtected per table.
	byTable := map[string][]Column{}
	for _, c := range allCols {
		byTable[c.TableName] = append(byTable[c.TableName], c)
	}

	var findings []scanner.Finding
	var metas []sqlFindingMeta
	for _, c := range allCols {
		panProtected := isPANProtectedInTable(byTable[c.TableName])
		if !isSensitiveColumnInContext(c.TableName, c.Name, panProtected) {
			continue
		}
		// exp_date exemption. If this column is an expiry column AND
		// PAN in the same table is protected (bytea type), suppress entirely.
		// PCI DSS allows storing expiry when PAN is rendered unreadable.
		if IsSQLExpiryColumn(c.Name) && panProtected {
			continue
		}
		findings = append(findings, scanner.Finding{
			RuleID:        RuleSQLSensitiveColumn,
			Severity:      scanner.SeverityHigh,
			RequirementID: "3.3.1",
			FilePath:      path,
			Line:          c.Line,
			Description: fmt.Sprintf(
				"Sensitive column %q declared in SQL schema. PCI DSS 3.3.1 forbids storing Sensitive Authentication Data (track data, CVV, PIN block) after authorization. For PAN, storage must be rendered unreadable per 3.5.1.",
				c.Name,
			),
			Suggestion:        "If this column stores SAD (CVV/track/PIN) drop it. If it stores PAN, change the column type to bytea and encrypt at the application layer via a BeforeCreate/BeforeSave hook.",
			SQLPatternMatched: true,
			Confidence:        "high",
		})
		metas = append(metas, sqlFindingMeta{TableName: c.TableName, ColumnName: c.Name})
		if IsPlaintextStringType(c.SQLType) {
			findings = append(findings, scanner.Finding{
				RuleID:        RuleSQLTextType,
				Severity:      scanner.SeverityMedium,
				RequirementID: "3.5.1",
				FilePath:      path,
				Line:          c.Line,
				Description: fmt.Sprintf(
					"Sensitive column %q stored as plaintext type %q. PCI DSS 3.5.1 requires PAN/SAD to be rendered unreadable at rest (use bytea + application-level encryption).",
					c.Name, c.SQLType,
				),
				Suggestion:        "Change the column type to bytea and encrypt at the application layer before insertion.",
				SQLPatternMatched: true,
				Confidence:        "high",
			})
			metas = append(metas, sqlFindingMeta{TableName: c.TableName, ColumnName: c.Name})
		}
	}
	return findings, metas, lineCount, nil
}

// isPANProtectedInTable scans columns in a table for PAN-like column names
// and checks whether their SQL type is bytea (encrypted). Returns true if
// no PAN-like column exists or if a PAN-like column uses bytea.
func isPANProtectedInTable(columns []Column) bool {
	for _, c := range columns {
		norm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(c.Name, "_", ""), "-", ""))
		isPAN := isSensitiveColumn(c.Name) || norm == "number" || norm == "account"
		if isPAN {
			if strings.ToLower(c.SQLType) == "bytea" {
				return true
			}
			return false // PAN exists as non-bytea
		}
	}
	return true // no PAN-like column -> panProtected=true
}

// scanGoFileWithStructs parses a Go file and emits GORM-SENSITIVE-TAG /
// GORM-NO-ENCRYPT-HOOK findings using context-aware matching with per-field
// encryption severity, and returns GormStruct metadata for cross-reference
// with SQL findings. Reuses the same ParseGormStructsWithContext call to
// avoid double-parsing.
func (s *SQLScanner) scanGoFileWithStructs(path string) ([]scanner.Finding, []GormStruct, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		// Parse errors on individual files should not kill the whole scan.
		return nil, nil, 0, nil
	}
	if file == nil {
		return nil, nil, 0, nil
	}
	lineCount := fset.Position(file.End()).Line

	parsed := ParseGormStructsWithContext(file, fset)

	var findings []scanner.Finding
	for _, gs := range parsed {
		for _, tag := range gs.SensitiveTags {
			sev := scanner.SeverityHigh
			triage := "Struct has no BeforeCreate/BeforeSave/BeforeUpdate/AfterFind method referencing Encrypt/Decrypt."

			if gs.EncryptedFields[tag.FieldName] {
				// Field-level encryption detected.
				sev = scanner.SeverityInfo
				triage = "Encryption hook detected — field-level Encrypt/Decrypt wired for this field."
			} else if gs.HasEncryptHook {
				// Struct has hooks but this field is not individually encrypted.
				// Check if this is an expiry keyword — MEDIUM severity.
				normCol := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(tag.ColumnName, "_", ""), "-", ""))
				if expiryKeywords[normCol] {
					sev = scanner.SeverityMedium
					triage = "Expiry field exposed alongside encrypted PAN. PCI DSS 3.3.1.1 allows expiry only when PAN is rendered unreadable."
				} else {
					sev = scanner.SeverityInfo
					triage = "Encryption hook detected (BeforeCreate/BeforeSave/BeforeUpdate/AfterFind references Encrypt/Decrypt)."
				}
			} else {
				// No encryption hooks at all.
				normCol := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(tag.ColumnName, "_", ""), "-", ""))
				if expiryKeywords[normCol] {
					sev = scanner.SeverityMedium
					triage = "Expiry field exposed alongside unprotected PAN."
				}
			}

			findings = append(findings, scanner.Finding{
				RuleID:        RuleGormSensitiveTag,
				Severity:      sev,
				RequirementID: "3.3.1",
				FilePath:      path,
				Line:          tag.Line,
				Description: fmt.Sprintf(
					"Struct %s field %s has sensitive DB column tag (%s:%q). %s",
					gs.Name, tag.FieldName, tag.TagSource, tag.ColumnName, triage,
				),
				Suggestion:        "Ensure the field is encrypted at the application layer via BeforeCreate/BeforeSave/BeforeUpdate hooks that call your Encrypt/Decrypt helper.",
				SQLPatternMatched: true,
				TriageHint:        triage,
				Confidence:        "high",
			})
		}
		if len(gs.SensitiveTags) > 0 && !gs.HasEncryptHook {
			findings = append(findings, scanner.Finding{
				RuleID:        RuleGormNoEncryptHook,
				Severity:      scanner.SeverityHigh,
				RequirementID: "3.5.1",
				FilePath:      path,
				Line:          gs.Line,
				Description: fmt.Sprintf(
					"Struct %s stores sensitive cardholder columns but has no BeforeCreate/BeforeSave/BeforeUpdate/AfterFind method referencing Encrypt/Decrypt. PCI DSS 3.5.1 requires PAN/SAD to be rendered unreadable at rest.",
					gs.Name,
				),
				Suggestion:        "Add a (m *Struct) BeforeCreate(tx *gorm.DB) error hook that calls your Encrypt helper on sensitive fields before persistence.",
				SQLPatternMatched: true,
				Confidence:        "high",
			})
		}
	}
	return findings, parsed, lineCount, nil
}

// crossRefSQLWithGoEncryption downgrades SQL-SENSITIVE-COLUMN findings to
// INFO when a matching Go struct has application-level encryption for the
// flagged column. Also suppresses SQL expiry findings when Go-level PAN
// encryption is detected ( + combined).
//
// It operates on result.Findings[sqlStart:sqlEnd] using parallel sqlMetas.
// Returns the full findings slice with modifications applied in-place.
func crossRefSQLWithGoEncryption(
	findings []scanner.Finding,
	sqlStart, sqlEnd int,
	sqlMetas []sqlFindingMeta,
	goEncrypt map[string]goEncryptInfo,
) []scanner.Finding {
	if sqlStart >= sqlEnd || len(sqlMetas) == 0 {
		return findings
	}

	// Build a set of tables with Go-level PAN encryption.
	tablesWithPANEncrypt := map[string]bool{}
	for key, info := range goEncrypt {
		if !info.HasEncryptHook {
			continue
		}
		// Check if any PAN-like column is encrypted.
		for col, fieldName := range info.ColumnToField {
			normCol := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(col, "_", ""), "-", ""))
			isPAN := isSensitiveColumn(col) || normCol == "number" || normCol == "account"
			if isPAN && info.EncryptedFields[fieldName] {
				tablesWithPANEncrypt[key] = true
				break
			}
		}
	}

	// Walk SQL findings and their metadata in parallel.
	// sqlMetas[i] corresponds to findings[sqlStart + metaOffset] where metaOffset
	// tracks the position. But note: scanSQLFileWithMeta emits one meta per
	// SQL-SENSITIVE-COLUMN and one per SQL-TEXT-TYPE. We need to match them.
	metaIdx := 0
	var suppress []int // indices into findings to remove
	for i := sqlStart; i < sqlEnd && metaIdx < len(sqlMetas); i++ {
		f := &findings[i]
		meta := sqlMetas[metaIdx]
		metaIdx++

		tableKey := strings.ToLower(meta.TableName)
		info, hasGoStruct := goEncrypt[tableKey]

		if f.RuleID == RuleSQLSensitiveColumn {
			// extended: suppress expiry columns when Go-level PAN encryption detected.
			if IsSQLExpiryColumn(meta.ColumnName) && tablesWithPANEncrypt[tableKey] {
				suppress = append(suppress, i)
				continue
			}

			// downgrade to INFO when Go struct has encrypt hook for this column.
			if hasGoStruct && info.HasEncryptHook {
				colLower := strings.ToLower(meta.ColumnName)
				goField := info.ColumnToField[colLower]
				if goField != "" && info.EncryptedFields[goField] {
					f.Severity = scanner.SeverityInfo
					f.TriageHint = "App-level encryption detected via gorm BeforeCreate/BeforeSave hook for this field."
					f.Description = fmt.Sprintf(
						"Sensitive column %q declared in SQL schema — app-level encryption detected via gorm hook. "+
							"PCI DSS 3.3.1 forbids storing SAD after authorization; PAN must be rendered unreadable per 3.5.1.",
						meta.ColumnName,
					)
				}
			}
		} else if f.RuleID == RuleSQLTextType {
			// SQL-TEXT-TYPE: if the column has Go-level encryption, downgrade too.
			if hasGoStruct && info.HasEncryptHook {
				colLower := strings.ToLower(meta.ColumnName)
				goField := info.ColumnToField[colLower]
				if goField != "" && info.EncryptedFields[goField] {
					f.Severity = scanner.SeverityInfo
					f.TriageHint = "App-level encryption detected via gorm hook — SQL type is plaintext but data is encrypted before storage."
				}
			}
		}
	}

	// Remove suppressed findings (iterate backwards to preserve indices).
	if len(suppress) > 0 {
		for i := len(suppress) - 1; i >= 0; i-- {
			idx := suppress[i]
			findings = append(findings[:idx], findings[idx+1:]...)
		}
	}

	return findings
}
