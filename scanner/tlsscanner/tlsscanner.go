package tlsscanner

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
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

// TLSScanner detects TLS configuration violations in Go source files.
type TLSScanner struct{}

// New creates a new TLSScanner instance.
func New() *TLSScanner {
	return &TLSScanner{}
}

// Name implements scanner.Scanner.
func (s *TLSScanner) Name() string {
	return "tls_config"
}

// Description implements scanner.Scanner.
func (s *TLSScanner) Description() string {
	return "Detect TLS configuration violations in Go source files"
}

// Requirements implements scanner.Scanner.
func (s *TLSScanner) Requirements() []string {
	return []string{"4.2.1"}
}

// Scan implements scanner.Scanner. Uses default exclude patterns.
func (s *TLSScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanWithExclusions(ctx, targetPath, defaultExcludePatterns)
}

// ScanWithExclusions scans the target path with custom exclude patterns.
func (s *TLSScanner) ScanWithExclusions(ctx context.Context, targetPath string, excludePatterns []string) (*scanner.ScanResult, error) {
	return s.ScanFull(ctx, targetPath, excludePatterns, false, false)
}

// ScanFull scans with full control over exclusions, test file inclusion, and git tracking.
func (s *TLSScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
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
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if err != nil {
			return nil, fmt.Errorf("walking files: %w", err)
		}

		findings, lines, scanErr := scanGoFile(path)
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

// scanGoFile parses a Go source file and applies all TLS detection rules.
func scanGoFile(path string) ([]scanner.Finding, int, error) {
	file, fset, err := scanner.ParseGoFile(path)
	if err != nil {
		return nil, 0, err
	}

	// Skip generated files.
	if ast.IsGenerated(file) {
		return nil, 0, nil
	}

	lineCount := fset.Position(file.End()).Line

	// Resolve the import alias for "crypto/tls".
	tlsAlias := resolveTLSAlias(file)
	if tlsAlias == "" {
		// File does not import crypto/tls -- no TLS findings possible.
		return nil, lineCount, nil
	}

	findings := scanTLSConfig(file, fset, path, tlsAlias)
	return findings, lineCount, nil
}

// resolveTLSAlias walks file imports and returns the local name for "crypto/tls".
// Returns "" if crypto/tls is not imported.
func resolveTLSAlias(file *ast.File) string {
	for _, imp := range file.Imports {
		// Import path is a string literal with quotes.
		importPath := strings.Trim(imp.Path.Value, `"`)
		if importPath != "crypto/tls" {
			continue
		}
		if imp.Name != nil {
			// Explicit alias: import ctls "crypto/tls"
			return imp.Name.Name
		}
		// Default: last path element.
		return filepath.Base(importPath)
	}
	return ""
}

// scanTLSConfig detects TLS configuration issues in the file.
func scanTLSConfig(file *ast.File, fset *token.FileSet, path, tlsAlias string) []scanner.Finding {
	var findings []scanner.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			f := inspectCompositeLit(node, fset, path, tlsAlias)
			findings = append(findings, f...)

		case *ast.AssignStmt:
			f := inspectAssignment(node, fset, path)
			findings = append(findings, f...)
		}
		return true
	})

	return findings
}

// inspectCompositeLit checks if a composite literal is a tls.Config and inspects its fields.
func inspectCompositeLit(lit *ast.CompositeLit, fset *token.FileSet, path, tlsAlias string) []scanner.Finding {
	if !isTLSConfigType(lit.Type, tlsAlias) {
		return nil
	}

	var findings []scanner.Finding
	hasMinVersion := false

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}

		switch keyIdent.Name {
		case "InsecureSkipVerify":
			if isTrueIdent(kv.Value) {
				pos := fset.Position(kv.Key.Pos())
				findings = append(findings, scanner.Finding{
					RuleID:              "TLS-INSECURE-SKIP-VERIFY",
					Severity:            scanner.SeverityCritical,
					RequirementID:       "4.2.1",
					FilePath:            path,
					Line:                pos.Line,
					Column:              pos.Column,
					Description:         "InsecureSkipVerify set to true disables TLS certificate verification",
					Suggestion:          "Remove InsecureSkipVerify: true. Use proper certificate validation in production.",
					RelatedRequirements: []string{"4.2.1.1", "2.2.7"},
				})
			}

		case "MinVersion":
			hasMinVersion = true
			if versionName := selectorName(kv.Value); versionName != "" && isWeakTLSVersion(versionName) {
				pos := fset.Position(kv.Key.Pos())
				findings = append(findings, scanner.Finding{
					RuleID:        "TLS-WEAK-VERSION",
					Severity:      scanner.SeverityCritical,
					RequirementID: "4.2.1",
					FilePath:      path,
					Line:          pos.Line,
					Column:        pos.Column,
					Description:   fmt.Sprintf("MinVersion set to %s which is below TLS 1.2", versionName),
					Suggestion:    "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
				})
			}

		case "CipherSuites":
			f := inspectCipherSuites(kv.Value, fset, path)
			findings = append(findings, f...)
		}
	}

	// Missing MinVersion check: only from composite literals where we can detect absence.
	if !hasMinVersion {
		pos := fset.Position(lit.Pos())
		findings = append(findings, scanner.Finding{
			RuleID:        "TLS-MISSING-MIN-VERSION",
			Severity:      scanner.SeverityHigh,
			RequirementID: "4.2.1",
			FilePath:      path,
			Line:          pos.Line,
			Column:        pos.Column,
			Description:   "tls.Config without explicit MinVersion defaults to TLS 1.0",
			Suggestion:    "Set MinVersion: tls.VersionTLS12 to enforce minimum TLS 1.2.",
		})
	}

	return findings
}

// inspectAssignment checks field assignments for InsecureSkipVerify and MinVersion.
func inspectAssignment(stmt *ast.AssignStmt, fset *token.FileSet, path string) []scanner.Finding {
	var findings []scanner.Finding

	for i, lhs := range stmt.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok {
			continue
		}

		switch sel.Sel.Name {
		case "InsecureSkipVerify":
			if i < len(stmt.Rhs) && isTrueIdent(stmt.Rhs[i]) {
				pos := fset.Position(sel.Pos())
				findings = append(findings, scanner.Finding{
					RuleID:              "TLS-INSECURE-SKIP-VERIFY",
					Severity:            scanner.SeverityCritical,
					RequirementID:       "4.2.1",
					FilePath:            path,
					Line:                pos.Line,
					Column:              pos.Column,
					Description:         "InsecureSkipVerify set to true via field assignment disables TLS certificate verification",
					Suggestion:          "Remove the InsecureSkipVerify = true assignment. Use proper certificate validation.",
					RelatedRequirements: []string{"4.2.1.1", "2.2.7"},
				})
			}

		case "MinVersion":
			if i < len(stmt.Rhs) {
				if versionName := selectorName(stmt.Rhs[i]); versionName != "" && isWeakTLSVersion(versionName) {
					pos := fset.Position(sel.Pos())
					findings = append(findings, scanner.Finding{
						RuleID:        "TLS-WEAK-VERSION",
						Severity:      scanner.SeverityCritical,
						RequirementID: "4.2.1",
						FilePath:      path,
						Line:          pos.Line,
						Column:        pos.Column,
						Description:   fmt.Sprintf("MinVersion set to %s via field assignment, which is below TLS 1.2", versionName),
						Suggestion:    "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13.",
					})
				}
			}
		}
	}

	return findings
}

// inspectCipherSuites checks a CipherSuites composite literal value for prohibited ciphers.
func inspectCipherSuites(expr ast.Expr, fset *token.FileSet, path string) []scanner.Finding {
	// The value should be a composite literal []uint16{...}.
	compLit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil
	}

	var findings []scanner.Finding
	for _, elt := range compLit.Elts {
		cipherName := selectorName(elt)
		if cipherName == "" {
			continue
		}
		if isProhibitedCipher(cipherName) {
			pos := fset.Position(elt.Pos())
			findings = append(findings, scanner.Finding{
				RuleID:        "TLS-WEAK-CIPHER",
				Severity:      scanner.SeverityCritical,
				RequirementID: "4.2.1",
				FilePath:      path,
				Line:          pos.Line,
				Column:        pos.Column,
				Description:   fmt.Sprintf("Prohibited cipher suite %s", cipherName),
				Suggestion:    "Remove prohibited cipher suite. Use AES-GCM or ChaCha20-Poly1305 cipher suites.",
			})
		}
	}
	return findings
}

// isTLSConfigType checks if a type expression is {alias}.Config.
func isTLSConfigType(expr ast.Expr, tlsAlias string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == tlsAlias && sel.Sel.Name == "Config"
}

// isTrueIdent checks if an expression is the identifier "true".
func isTrueIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "true"
}

// selectorName extracts the Sel.Name from a SelectorExpr (e.g., tls.VersionTLS12 -> "VersionTLS12").
// Returns "" if the expression is not a SelectorExpr.
func selectorName(expr ast.Expr) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}
