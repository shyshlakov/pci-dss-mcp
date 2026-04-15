package authscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/cryptoscanner"
)

// passwordKeywords are variable name keywords that indicate password storage.
// Uses word boundary matching to avoid false positives like "passkey" or "bypass".
// Short ambiguous keywords "pass" and "pwd" removed (too many FPs).
var passwordKeywords = []string{
	"password", "passwd", "passphrase", "dbpass", "dbpwd",
}

// setenvSecretKeywords are os.Setenv first-argument keywords that indicate secrets.
// Matching is case-insensitive.
var setenvSecretKeywords = []string{
	"password", "passwd", "api_key", "apikey", "token", "secret",
}

// isPasswordName returns true if the variable name contains a password-related
// keyword at a word boundary. Uses CamelCase/snake_case splitting to avoid
// false positives like "passkeyGroup" or "bypassAuth".
func isPasswordName(name string) bool {
	for _, kw := range passwordKeywords {
		if cryptoscanner.IsKeywordAtWordBoundary(name, kw) {
			return true
		}
	}
	return false
}

// isSecretEnvKey returns true if the environment variable key contains a secret keyword.
func isSecretEnvKey(key string) bool {
	lower := strings.ToLower(key)
	for _, kw := range setenvSecretKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isPlaceholder returns true for placeholder values that should be downgraded to INFO.
// Covers: empty strings, changeme/placeholder/todo, ${...} templates, <...> brackets, all-x.
func isPlaceholder(value string) bool {
	// Empty string.
	if value == "" {
		return true
	}

	// Case-insensitive exact match for well-known placeholders.
	lower := strings.ToLower(value)
	switch lower {
	case "changeme", "placeholder", "todo":
		return true
	}

	// Environment variable template: ${...}.
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		return true
	}

	// Angle bracket placeholder: <...>.
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return true
	}

	// All-x string (every letter is 'x', case-insensitive).
	if isAllX(value) {
		return true
	}

	return false
}

// isAllX returns true if every character in the string is 'x' or 'X'.
func isAllX(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c != 'x' && c != 'X' {
			return false
		}
	}
	return true
}

// extractStringValue extracts the unquoted string value from a BasicLit or
// []byte conversion expression. Returns empty string if not a string literal.
func extractStringValue(expr ast.Expr) string {
	switch v := expr.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return ""
		}
		unquoted, err := strconv.Unquote(v.Value)
		if err != nil {
			return ""
		}
		return unquoted
	case *ast.CallExpr:
		// Handle []byte("...") conversion.
		if len(v.Args) == 1 {
			return extractStringValue(v.Args[0])
		}
	}
	return ""
}

// isOsSetenvCall returns true if the call expression is os.Setenv.
func isOsSetenvCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "os" && sel.Sel.Name == "Setenv"
}

// detectHardcodedPasswords is the legacy entry point that delegates to
// detectHardcodedPasswordsInRoot with an empty scan root. Kept for in-package
// tests that predate the project-root-aware devcontext fix.
func detectHardcodedPasswords(file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	return detectHardcodedPasswordsInRoot(file, fset, path, "")
}

// detectHardcodedPasswordsInRoot detects hardcoded passwords in variable
// declarations, assignments, and os.Setenv calls. projectRoot is forwarded to
// ClassifyDevContextInRoot so ancestor directory segments are stripped before
// dev-path matching.
func detectHardcodedPasswordsInRoot(file *ast.File, fset *token.FileSet, path, projectRoot string) []scanner.Finding {
	var findings []scanner.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			findings = append(findings, passwordsFromValueSpec(node, fset, path, projectRoot)...)
		case *ast.AssignStmt:
			findings = append(findings, passwordsFromAssign(node, fset, path, projectRoot)...)
		case *ast.CallExpr:
			if f := passwordFromSetenv(node, fset, path, projectRoot); f != nil {
				findings = append(findings, *f)
			}
		}
		return true
	})

	return findings
}

// applyAuthDevContext applies ClassifyDevContextInRoot adjustments in place.
func applyAuthDevContext(finding *scanner.Finding, strVal, path, projectRoot string) {
	dc := scanner.ClassifyDevContextInRoot(path, strVal, finding.Severity, projectRoot)
	finding.Severity = dc.AdjustedSev
	if dc.DedicatedDev && !dc.IsProdPath {
		finding.Severity = scanner.SeverityInfo
	}
	if dc.DedicatedDev || dc.IsDevPath || dc.IsPlaceholder {
		finding.DevContext = true
	}
	if dc.Label != "" {
		finding.Description = finding.Description + " [" + dc.Label + "]"
	}
}

// buildPasswordFinding constructs an AUTH-HARDCODED-PWD finding for a literal
// password site and applies dev-context adjustments.
func buildPasswordFinding(varName, strVal, path, projectRoot string, pos token.Position) scanner.Finding {
	var finding scanner.Finding
	if isPlaceholder(strVal) {
		finding = scanner.Finding{
			RuleID:              "AUTH-HARDCODED-PWD",
			Severity:            scanner.SeverityInfo,
			RequirementID:       "8.3.1",
			FilePath:            path,
			Line:                pos.Line,
			Column:              pos.Column,
			Description:         fmt.Sprintf("Placeholder password in variable '%s' -- verify this is replaced before deployment", varName),
			Suggestion:          "Replace placeholder value with a runtime-loaded secret.",
			RelatedRequirements: []string{"8.6.2"},
		}
	} else {
		finding = scanner.Finding{
			RuleID:              "AUTH-HARDCODED-PWD",
			Severity:            scanner.SeverityCritical,
			RequirementID:       "8.3.1",
			FilePath:            path,
			Line:                pos.Line,
			Column:              pos.Column,
			Description:         fmt.Sprintf("Hardcoded password in variable '%s'", varName),
			Suggestion:          "Move passwords to environment variables or a secrets manager. Never commit passwords to source code.",
			RelatedRequirements: []string{"8.6.2"},
		}
	}
	applyAuthDevContext(&finding, strVal, path, projectRoot)
	return finding
}

// passwordsFromValueSpec emits findings for var/const password-named
// declarations like `var password = "value"`.
func passwordsFromValueSpec(node *ast.ValueSpec, fset *token.FileSet, path, projectRoot string) []scanner.Finding {
	var findings []scanner.Finding
	for i, name := range node.Names {
		if !isPasswordName(name.Name) || i >= len(node.Values) {
			continue
		}
		strVal := extractStringValue(node.Values[i])
		if strVal == "" && !isStringLiteral(node.Values[i]) {
			continue
		}
		pos := fset.Position(node.Values[i].Pos())
		findings = append(findings, buildPasswordFinding(name.Name, strVal, path, projectRoot, pos))
	}
	return findings
}

// passwordsFromAssign emits findings for password-named assignments like
// `password := "value"` or `password = "value"`.
func passwordsFromAssign(node *ast.AssignStmt, fset *token.FileSet, path, projectRoot string) []scanner.Finding {
	var findings []scanner.Finding
	for i, lhs := range node.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok || !isPasswordName(ident.Name) || i >= len(node.Rhs) {
			continue
		}
		strVal := extractStringValue(node.Rhs[i])
		if strVal == "" && !isStringLiteral(node.Rhs[i]) {
			continue
		}
		pos := fset.Position(node.Rhs[i].Pos())
		findings = append(findings, buildPasswordFinding(ident.Name, strVal, path, projectRoot, pos))
	}
	return findings
}

// passwordFromSetenv emits a finding for `os.Setenv("DB_PASSWORD", "secret")`
// style calls when the key is a recognized secret env var and the value is a
// string literal. Returns nil when the call doesn't match.
func passwordFromSetenv(node *ast.CallExpr, fset *token.FileSet, path, projectRoot string) *scanner.Finding {
	if !isOsSetenvCall(node) || len(node.Args) != 2 {
		return nil
	}
	keyStr := extractStringValue(node.Args[0])
	if keyStr == "" || !isSecretEnvKey(keyStr) {
		return nil
	}
	valStr := extractStringValue(node.Args[1])
	if valStr == "" && !isStringLiteral(node.Args[1]) {
		return nil
	}
	pos := fset.Position(node.Pos())
	finding := scanner.Finding{
		RuleID:              "AUTH-HARDCODED-PWD",
		Severity:            scanner.SeverityCritical,
		RequirementID:       "8.3.1",
		FilePath:            path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         fmt.Sprintf("Hardcoded secret in os.Setenv call with key '%s'", keyStr),
		Suggestion:          "Move secrets to environment variables loaded at runtime, not hardcoded in os.Setenv calls.",
		RelatedRequirements: []string{"8.6.2"},
	}
	applyAuthDevContext(&finding, valStr, path, projectRoot)
	return &finding
}

// isStringLiteral returns true if the expression is a string literal (including empty "").
func isStringLiteral(expr ast.Expr) bool {
	switch v := expr.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.CallExpr:
		// []byte("...") conversion.
		if len(v.Args) == 1 {
			return isStringLiteral(v.Args[0])
		}
	}
	return false
}
