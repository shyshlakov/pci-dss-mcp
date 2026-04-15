package cryptoscanner

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// httpURLPattern matches plain HTTP URLs in string literals.
var httpURLPattern = regexp.MustCompile(`http://[^\s"]+`)

// localhostExcludePattern matches localhost, 127.0.0.1, 0.0.0.0, and [::1] URLs.
var localhostExcludePattern = regexp.MustCompile(`^http://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.com)(:|/|$)`)

// checkPlainHTTP detects plain HTTP URLs that should use HTTPS.
// Localhost and loopback addresses are excluded.
func checkPlainHTTP(file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	var findings []scanner.Finding

	matches := scanner.InspectStringLiterals(file, fset, httpURLPattern)
	for _, m := range matches {
		if localhostExcludePattern.MatchString(m.Value) {
			continue
		}

		findings = append(findings, scanner.Finding{
			RuleID:        "CRYPTO-PLAIN-HTTP",
			Severity:      scanner.SeverityCritical,
			RequirementID: "4.2.1",
			FilePath:      path,
			Line:          m.Position.Line,
			Column:        m.Position.Column,
			Description:   "Plain HTTP URL detected: " + m.Value + " -- data in transit is not encrypted",
			Suggestion:    "Use HTTPS instead of HTTP for all network communication to protect data in transit.",
		})
	}

	return findings
}
