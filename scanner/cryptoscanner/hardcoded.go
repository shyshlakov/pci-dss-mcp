package cryptoscanner

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// keyRelatedKeywords are variable name keywords that indicate key/secret storage.
var keyRelatedKeywords = []string{
	"key", "secret", "iv", "token", "password", "salt", "credential", "apikey",
}

// Compiled regex patterns for exclusions and pattern matching.
var (
	semverPattern = regexp.MustCompile(`^v?\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?$`)
	urlPattern    = regexp.MustCompile(`^https?://`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]{32,}={0,2}$`)
	hexPattern    = regexp.MustCompile(`^(0x)?[0-9a-fA-F]{16,}$`)
)

// nonSecretPatterns identify values that look like non-secret data:
// dotted routing keys, URL paths, UPPER_CASE enums. Note: the camelCase
// identifier heuristic is not part of this list because a pure regex match
// collides with random secrets that happen to start lowercase and contain an
// uppercase letter (e.g. "zX9vQm2tL8jKrB4nYpF6sW1eR7aC3hGdJkMo"). It is
// evaluated separately in looksLikeCamelCaseIdentifier with a length cap and
// digit-density guard.
var nonSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`), // dotted.routing.keys
	// URL-shaped values with dots and longer multi-segment paths.
	// Requires at least two slash-separated segments (so a bare /etc does not match)
	// and allows dots inside segment names (common in API paths like /api/v1.0/foo).
	regexp.MustCompile(`^/[a-zA-Z0-9][a-zA-Z0-9_\-.]*(/[a-zA-Z0-9][a-zA-Z0-9_\-.]*)+$`), // URL paths with multiple segments, dots OK
	regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`),                                             // UPPER_CASE_ENUMS
}

// camelCaseIdentifierPattern matches strings that are shaped like a camelCase
// Go identifier (lowercase start, at least one uppercase in the middle, only
// alphanumerics).
var camelCaseIdentifierPattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$`)

// looksLikeCamelCaseIdentifier returns true only for strings that are plausibly
// Go identifiers rather than random secrets. A real camelCase identifier is
// short (<= 32 chars) and contains at most a handful of digits. Longer strings
// or strings with many digits are more likely to be high-entropy secrets that
// only incidentally satisfy the regex.
func looksLikeCamelCaseIdentifier(val string) bool {
	if len(val) > 32 {
		return false
	}
	if !camelCaseIdentifierPattern.MatchString(val) {
		return false
	}
	digits := 0
	for i := 0; i < len(val); i++ {
		if val[i] >= '0' && val[i] <= '9' {
			digits++
		}
	}
	// Real identifiers like oauth2Token / bearer1Token rarely exceed 3 digits.
	return digits <= 3
}

// isCharacterSet returns true for strings that look like a
// generator alphabet or character set (e.g., const alphanum = "ABC...xyz0123456789").
// ALL three conditions must hold:
// 1. Length >= 20
// 2. Unique byte count >= 70% of length (each char appears roughly once)
// 3. Either contains a 10-char strictly increasing alphabetic run (A,B,C,...)
// OR contains the literal substring "0123456789"
//
// Random-looking secrets that merely have high unique-byte counts do not satisfy
// condition 3 and are therefore still flagged as potential secrets.
func isCharacterSet(val string) bool {
	if len(val) < 20 {
		return false
	}
	seen := make(map[byte]bool, len(val))
	for i := 0; i < len(val); i++ {
		seen[val[i]] = true
	}
	// Unique-byte ratio >= 70% using integer arithmetic to avoid float rounding.
	if len(seen)*100 < len(val)*70 {
		return false
	}
	if strings.Contains(val, "0123456789") {
		return true
	}
	return hasAlphabetRun(val, 10)
}

// hasAlphabetRun returns true if val contains a substring of n consecutive
// alphabetic characters whose bytes are strictly increasing by 1 (A,B,C,... or
// a,b,c,...). Any non-alphabetic byte or a break in the +1 sequence resets the
// run counter.
func hasAlphabetRun(val string, n int) bool {
	if n <= 0 || len(val) < n {
		return false
	}
	run := 1
	for i := 1; i < len(val); i++ {
		if isAlphaByte(val[i]) && isAlphaByte(val[i-1]) && val[i] == val[i-1]+1 {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 1
		}
	}
	return false
}

// isAlphaByte reports whether b is an ASCII alphabetic character.
func isAlphaByte(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// sqlQueryPattern matches SQL statement prefixes. SQL queries are never
// secrets -- exclude before entropy analysis.
var sqlQueryPattern = regexp.MustCompile(`(?i)^\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE|DROP|ALTER|WITH)\s+`)

// isSQLQuery returns true if the value looks like an SQL query string.
// SQL queries can never be secrets.
func isSQLQuery(val string) bool {
	return sqlQueryPattern.MatchString(val)
}

// nonSecretPrefixes are case-insensitive value prefixes indicating error messages.
var nonSecretPrefixes = []string{
	"invalid ", "missing ", "bad ", "unknown ", "error ", "err ",
	"failed ", "cannot ", "could not ", "unable to ",
}

// isNonSecretValue returns true if the value matches patterns typical of
// non-secret data: routing keys, URL paths, enums, error messages, identifiers.
func isNonSecretValue(val string) bool {
	for _, pat := range nonSecretPatterns {
		if pat.MatchString(val) {
			return true
		}
	}
	if looksLikeCamelCaseIdentifier(val) {
		return true
	}
	lower := strings.ToLower(val)
	for _, prefix := range nonSecretPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// checkHardcodedKeys is the legacy entry point that delegates to
// checkHardcodedKeysInRoot with an empty scan root. Kept for in-package tests
// that predate the project-root-aware devcontext fix.
func checkHardcodedKeys(file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	return checkHardcodedKeysInRoot(file, fset, path, "")
}

// checkHardcodedKeysInRoot detects hardcoded encryption keys, IVs, and secrets using
// three-tier detection. projectRoot is forwarded to checkAssignmentInRoot so
// devcontext segment matching can strip ancestor directories.
//
//	Tier 1: Keyword in variable name + string literal -> CRITICAL
//	Tier 2: High Shannon entropy (>4.5, >=16 chars) -> HIGH
//	Tier 3: Base64 (>=32 chars) or hex (>=16 hex chars) pattern -> HIGH
func checkHardcodedKeysInRoot(file *ast.File, fset *token.FileSet, path, projectRoot string) []scanner.Finding {
	var findings []scanner.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			// var secretKey = "value" or var secretKey string = "value"
			for i, name := range node.Names {
				if i >= len(node.Values) {
					continue
				}
				val := node.Values[i]
				finding := checkAssignmentInRoot(name.Name, val, fset, path, projectRoot)
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		case *ast.AssignStmt:
			// secretKey:= "value" or secretKey = "value"
			for i, lhs := range node.Lhs {
				if i >= len(node.Rhs) {
					continue
				}
				ident, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				finding := checkAssignmentInRoot(ident.Name, node.Rhs[i], fset, path, projectRoot)
				if finding != nil {
					findings = append(findings, *finding)
				}
			}
		}
		return true
	})

	return findings
}

// checkAssignment is the legacy entry point that delegates to
// checkAssignmentInRoot with an empty scan root. Kept for in-package tests.
func checkAssignment(varName string, value ast.Expr, fset *token.FileSet, path string) *scanner.Finding {
	return checkAssignmentInRoot(varName, value, fset, path, "")
}

func detectInitExpr(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

func checkAssignmentInRoot(varName string, value ast.Expr, fset *token.FileSet, path, projectRoot string) *scanner.Finding {
	strVal := extractStringValue(value)
	if strVal == "" || isExcluded(strVal) || isSQLQuery(strVal) || isCharacterSet(strVal) {
		return nil
	}

	initExpr := detectInitExpr(value)
	pos := fset.Position(value.Pos())

	var finding *scanner.Finding
	if f := checkTier1KeywordMatch(varName, strVal, pos, path, projectRoot); f != nil {
		finding = f
	} else if f := checkTier2HighEntropy(varName, strVal, pos, path, projectRoot); f != nil {
		finding = f
	} else if f := checkTier3EncodedPattern(varName, strVal, pos, path, projectRoot); f != nil {
		finding = f
	}
	if finding == nil {
		return nil
	}
	filtered := ApplyHardcodedFilter(*finding, varName, strVal, initExpr)
	return &filtered
}

// applyDevContext adjusts the finding's severity and description based on the
// dev-context classification of the enclosing path. Dedicated dev segments
// that are not in prod paths downgrade to Info; any dev-related context marks
// DevContext=true; non-empty dev labels are appended to the description.
func applyDevContext(finding *scanner.Finding, strVal, path, projectRoot string) {
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

// checkTier1KeywordMatch: variable name contains a key-related keyword at a
// word boundary. Uses CamelCase word-boundary detection to eliminate false
// positives like LogKeyRequestID while preserving true positives like
// consumerKey. Respects the entropy floor and non-secret value patterns.
func checkTier1KeywordMatch(varName, strVal string, pos token.Position, path, projectRoot string) *scanner.Finding {
	var matched bool
	for _, kw := range keyRelatedKeywords {
		if IsKeywordAtWordBoundary(varName, kw) {
			matched = true
			break
		}
	}
	if !matched {
		return nil
	}
	if scanner.ShannonEntropy(strVal) < 3.0 {
		return nil
	}
	if isNonSecretValue(strVal) {
		return nil
	}
	finding := &scanner.Finding{
		RuleID:              "CRYPTO-HARDCODED-KEY",
		Severity:            scanner.SeverityCritical,
		RequirementID:       "6.2.4",
		FilePath:            path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         "Hardcoded secret in variable '" + varName + "' -- key-related keyword detected",
		Suggestion:          "Move secrets to environment variables or a secrets manager. Never commit secrets to source code.",
		RelatedRequirements: []string{"8.6.2"},
	}
	applyDevContext(finding, strVal, path, projectRoot)
	return finding
}

// checkTier2HighEntropy: high Shannon entropy (> 4.5 bits/char) on values of
// at least 16 characters. Short or low-entropy values fall through.
func checkTier2HighEntropy(varName, strVal string, pos token.Position, path, projectRoot string) *scanner.Finding {
	if len(strVal) < 16 || scanner.ShannonEntropy(strVal) <= 4.5 {
		return nil
	}
	if isNonSecretValue(strVal) {
		return nil
	}
	finding := &scanner.Finding{
		RuleID:              "CRYPTO-HARDCODED-KEY",
		Severity:            scanner.SeverityHigh,
		RequirementID:       "6.2.4",
		FilePath:            path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         "Possible hardcoded key in variable '" + varName + "' -- high entropy string detected, manual review recommended",
		Suggestion:          "Verify this is not a secret. Move sensitive values to environment variables or a secrets manager.",
		RelatedRequirements: []string{"8.6.2"},
	}
	applyDevContext(finding, strVal, path, projectRoot)
	return finding
}

// checkTier3EncodedPattern: base64 or hex pattern match. Non-secret value
// patterns (API paths, enums) are filtered out before flagging.
func checkTier3EncodedPattern(varName, strVal string, pos token.Position, path, projectRoot string) *scanner.Finding {
	if !base64Pattern.MatchString(strVal) && !hexPattern.MatchString(strVal) {
		return nil
	}
	if isNonSecretValue(strVal) {
		return nil
	}
	finding := &scanner.Finding{
		RuleID:              "CRYPTO-HARDCODED-KEY",
		Severity:            scanner.SeverityHigh,
		RequirementID:       "6.2.4",
		FilePath:            path,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         "Possible hardcoded key in variable '" + varName + "' -- encoded string pattern detected (base64/hex)",
		Suggestion:          "Verify this is not a secret. Move sensitive values to environment variables or a secrets manager.",
		RelatedRequirements: []string{"8.6.2"},
	}
	applyDevContext(finding, strVal, path, projectRoot)
	return finding
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

// isExcluded returns true if the string value should be excluded from key detection.
func isExcluded(val string) bool {
	// Exclude short strings (< 8 chars).
	if len(val) < 8 {
		return true
	}
	// Exclude semantic version strings.
	if semverPattern.MatchString(val) {
		return true
	}
	// Exclude URLs.
	if urlPattern.MatchString(val) {
		return true
	}
	// Exclude UUIDs.
	if uuidPattern.MatchString(val) {
		return true
	}
	return false
}
