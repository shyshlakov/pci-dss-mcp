package cryptoscanner

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// sensitiveKeywords are keywords indicating sensitive data context.
// Used for md5/sha1/des context scoring.
var sensitiveKeywords = []string{
	"password", "secret", "key", "token", "pan", "cvv", "card", "pin", "auth",
}

// passwordKeywords are password-specific keywords for sha256 detection.
var passwordKeywords = []string{
	"password", "passwd", "pwd",
}

// proximityLines is the number of lines to check for context around a call.
const proximityLines = 5

// checkWeakCrypto detects weak cryptographic algorithm usage with context scoring.
//
// Rules:
// - md5/sha1/des: CRITICAL if near sensitive keywords, INFO otherwise
// - sha256: CRITICAL if near password keywords, skip entirely otherwise
func checkWeakCrypto(file *ast.File, fset *token.FileSet, path string, importAliases map[string]string) []scanner.Finding {
	var findings []scanner.Finding

	// Build call patterns from resolved import aliases.
	type callTarget struct {
		pattern        string
		algo           string
		isSHA256       bool
		isDES          bool
		alwaysWeakAlgo bool // md5/sha1/des are always weak
	}

	var targets []callTarget

	// md5 patterns.
	if alias, ok := importAliases["crypto/md5"]; ok {
		targets = append(targets,
			callTarget{pattern: alias + ".New", algo: "MD5", alwaysWeakAlgo: true},
			callTarget{pattern: alias + ".Sum", algo: "MD5", alwaysWeakAlgo: true},
		)
	}

	// sha1 patterns.
	if alias, ok := importAliases["crypto/sha1"]; ok {
		targets = append(targets,
			callTarget{pattern: alias + ".New", algo: "SHA1", alwaysWeakAlgo: true},
			callTarget{pattern: alias + ".Sum", algo: "SHA1", alwaysWeakAlgo: true},
		)
	}

	// sha256 patterns.
	if alias, ok := importAliases["crypto/sha256"]; ok {
		targets = append(targets,
			callTarget{pattern: alias + ".New", algo: "SHA256", isSHA256: true},
			callTarget{pattern: alias + ".Sum256", algo: "SHA256", isSHA256: true},
		)
	}

	// des patterns.
	if alias, ok := importAliases["crypto/des"]; ok {
		targets = append(targets,
			callTarget{pattern: alias + ".NewCipher", algo: "DES", isDES: true, alwaysWeakAlgo: true},
			callTarget{pattern: alias + ".NewTripleDESCipher", algo: "3DES", isDES: true, alwaysWeakAlgo: true},
		)
	}

	if len(targets) == 0 {
		return nil
	}

	// Build pattern list for InspectCalls.
	patterns := make([]string, len(targets))
	patternMap := make(map[string]callTarget, len(targets))
	for i, t := range targets {
		patterns[i] = t.pattern
		patternMap[t.pattern] = t
	}

	calls := scanner.InspectCalls(file, fset, patterns...)

	for _, call := range calls {
		target := patternMap[call.FuncName]
		callLine := call.Position.Line

		if target.isSHA256 {
			// SHA256: only flag if near password keywords.
			funcBody := enclosingFuncBody(file, callLine, fset)
			if funcBody != nil && hasSensitiveContext(funcBody, callLine, fset, passwordKeywords) {
				findings = append(findings, scanner.Finding{
					RuleID:        "CRYPTO-WEAK-HASH",
					Severity:      scanner.SeverityCritical,
					RequirementID: "6.2.4",
					FilePath:      path,
					Line:          callLine,
					Column:        call.Position.Column,
					Description:   target.algo + " used for password hashing -- use a purpose-built password hash",
					Suggestion:    "Use bcrypt, argon2, or scrypt for password hashing instead of SHA256.",
				})
			}
			// Skip entirely if no password context.
			continue
		}

		// md5/sha1/des: check for sensitive context.
		funcBody := enclosingFuncBody(file, callLine, fset)
		if funcBody != nil && hasSensitiveContext(funcBody, callLine, fset, sensitiveKeywords) {
			findings = append(findings, scanner.Finding{
				RuleID:        "CRYPTO-WEAK-HASH",
				Severity:      scanner.SeverityCritical,
				RequirementID: "6.2.4",
				FilePath:      path,
				Line:          callLine,
				Column:        call.Position.Column,
				Description:   "Weak algorithm " + target.algo + " used near sensitive data",
				Suggestion:    "Replace " + target.algo + " with SHA-256 or stronger for data integrity. For passwords, use bcrypt or argon2.",
			})
		} else {
			findings = append(findings, scanner.Finding{
				RuleID:        "CRYPTO-WEAK-HASH",
				Severity:      scanner.SeverityInfo,
				RequirementID: "6.2.4",
				FilePath:      path,
				Line:          callLine,
				Column:        call.Position.Column,
				Description:   "Weak algorithm " + target.algo + " detected -- manual review recommended to verify usage context",
				Suggestion:    "Verify this usage is not for security-sensitive purposes. Consider replacing with SHA-256 or stronger.",
			})
		}
	}

	return findings
}

// enclosingFuncBody finds the function body (FuncDecl or FuncLit) that contains
// the given line number.
func enclosingFuncBody(file *ast.File, line int, fset *token.FileSet) *ast.BlockStmt {
	var result *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Body == nil {
				return true
			}
			start := fset.Position(node.Body.Lbrace).Line
			end := fset.Position(node.Body.Rbrace).Line
			if line >= start && line <= end {
				result = node.Body
			}
		case *ast.FuncLit:
			if node.Body == nil {
				return true
			}
			start := fset.Position(node.Body.Lbrace).Line
			end := fset.Position(node.Body.Rbrace).Line
			if line >= start && line <= end {
				result = node.Body
			}
		}
		return true
	})
	return result
}

// hasSensitiveContext checks if any identifier within +/-5 lines of callLine
// in the function body contains one of the given keywords (case-insensitive substring match).
func hasSensitiveContext(funcBody *ast.BlockStmt, callLine int, fset *token.FileSet, keywords []string) bool {
	found := false
	ast.Inspect(funcBody, func(n ast.Node) bool {
		if found {
			return false
		}
		ident, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		identLine := fset.Position(ident.Pos()).Line
		if abs(identLine-callLine) > proximityLines {
			return true
		}
		normalized := strings.ToLower(ident.Name)
		for _, kw := range keywords {
			if strings.Contains(normalized, kw) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// abs returns the absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
