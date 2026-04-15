package retentionscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/analysis"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// redisSetMethods are Redis methods that accept a TTL argument as 4th parameter.
var redisSetMethods = map[string]bool{
	"Set":   true,
	"SetNX": true,
}

// redisHSetMethods are Redis methods that store hash fields (no inline TTL).
var redisHSetMethods = map[string]bool{
	"HSet": true,
}

// expireMethodNames are Redis methods that set TTL on existing keys.
var expireMethodNames = map[string]bool{
	"Expire":   true,
	"ExpireAt": true,
	"ExpireNX": true,
}

// detectRedisWithoutTTL walks the AST for Redis Set/SetNX/HSet calls on
// sensitive data and flags those missing TTL or using KeepTTL.
func detectRedisWithoutTTL(file *ast.File, fset *token.FileSet, filePath string, aliases map[string]string) []scanner.Finding {
	var findings []scanner.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		methodName := sel.Sel.Name

		// Check Set/SetNX methods.
		if redisSetMethods[methodName] {
			f := checkRedisSetCall(call, sel, fset, filePath, methodName, file)
			findings = append(findings, f...)
			return true
		}

		// Check HSet methods.
		if redisHSetMethods[methodName] {
			f := checkRedisHSetCall(call, sel, fset, filePath, file)
			findings = append(findings, f...)
			return true
		}

		return true
	})

	return findings
}

// checkRedisSetCall checks a Set/SetNX call for TTL issues.
// Expected signature: rdb.Set(ctx, key, value, ttl)
func checkRedisSetCall(call *ast.CallExpr, sel *ast.SelectorExpr, fset *token.FileSet, filePath string, methodName string, file *ast.File) []scanner.Finding {
	// Need at least 4 args: ctx, key, value, ttl.
	if len(call.Args) < 4 {
		return nil
	}

	// Check if call involves sensitive data.
	if !callInvolvesSensitiveData(call) {
		return nil
	}

	ttlArg := call.Args[3]
	pos := fset.Position(call.Pos())

	// Check for KeepTTL.
	if isKeepTTL(ttlArg) {
		return []scanner.Finding{{
			RuleID:        "RET-REDIS-KEEP-TTL",
			Severity:      scanner.SeverityHigh,
			RequirementID: "3.2.1",
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf("Redis %s with KeepTTL on sensitive data. "+
				"KeepTTL preserves existing TTL but may be 0 if key is new. "+
				"PCI DSS 3.2.1 prohibits storing SAD after authorization.", methodName),
			Suggestion: "Set an explicit TTL instead of KeepTTL for sensitive data.",
		}}
	}

	// Check for zero TTL.
	if isZeroLiteral(ttlArg) {
		// For SetNX with TTL=0, check for nearby Expire.
		if methodName == "SetNX" {
			callLine := pos.Line
			if hasExpireNearby(file, fset, callLine, 5) {
				return nil
			}
		}
		return []scanner.Finding{{
			RuleID:        "RET-REDIS-NO-TTL",
			Severity:      scanner.SeverityCritical,
			RequirementID: "3.2.1",
			FilePath:      filePath,
			Line:          pos.Line,
			Column:        pos.Column,
			Description: fmt.Sprintf("Redis %s with TTL=0 on sensitive data -- data persists indefinitely. "+
				"PCI DSS 3.2.1 prohibits storing SAD after authorization.", methodName),
			Suggestion: "Set an explicit TTL (e.g., 5*time.Minute) for sensitive data.",
		}}
	}

	return nil
}

// checkRedisHSetCall checks an HSet call for missing Expire.
func checkRedisHSetCall(call *ast.CallExpr, sel *ast.SelectorExpr, fset *token.FileSet, filePath string, file *ast.File) []scanner.Finding {
	// Check if call involves sensitive data.
	if !callInvolvesSensitiveData(call) {
		return nil
	}

	pos := fset.Position(call.Pos())
	callLine := pos.Line

	// Check for Expire within 10 lines.
	if hasExpireNearby(file, fset, callLine, 10) {
		return nil
	}

	return []scanner.Finding{{
		RuleID:        "RET-REDIS-NO-EXPIRE",
		Severity:      scanner.SeverityHigh,
		RequirementID: "3.2.1",
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description: "Redis HSet on sensitive data without Expire call within 10 lines. " +
			"PCI DSS 3.2.1 prohibits storing SAD after authorization.",
		Suggestion: "Add rdb.Expire(ctx, key, ttl) after HSet for sensitive data.",
	}}
}

// callInvolvesSensitiveData checks if any argument in the call expression is
// a sensitive identifier (variable name or string key containing PAN/CVV/payment keywords).
func callInvolvesSensitiveData(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		if isSensitiveExpr(arg) {
			return true
		}
	}
	return false
}

// isSensitiveExpr checks if an expression references sensitive data.
func isSensitiveExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return analysis.IsSensitiveVarName(e.Name)
	case *ast.BasicLit:
		// Check string keys like "card_data", "payment_hash".
		if e.Kind == token.STRING {
			val := strings.Trim(e.Value, `"'`+"`")
			return analysis.IsSensitiveVarName(val)
		}
	case *ast.UnaryExpr:
		return isSensitiveExpr(e.X)
	case *ast.CompositeLit:
		// Check struct literal field names.
		if t, ok := e.Type.(*ast.Ident); ok && analysis.IsSensitiveVarName(t.Name) {
			return true
		}
		for _, elt := range e.Elts {
			if kv, ok := elt.(*ast.KeyValueExpr); ok {
				if isSensitiveExpr(kv.Key) || isSensitiveExpr(kv.Value) {
					return true
				}
			}
		}
	case *ast.SelectorExpr:
		return analysis.IsSensitiveVarName(e.Sel.Name)
	}
	return false
}

// isZeroLiteral checks for "0" literal or time.Duration(0).
func isZeroLiteral(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Value == "0"
	case *ast.CallExpr:
		// time.Duration(0) pattern.
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "Duration" {
				if len(e.Args) == 1 {
					if lit, ok := e.Args[0].(*ast.BasicLit); ok {
						return lit.Value == "0"
					}
				}
			}
		}
		// Duration(0) without package qualifier.
		if ident, ok := e.Fun.(*ast.Ident); ok {
			if ident.Name == "Duration" && len(e.Args) == 1 {
				if lit, ok := e.Args[0].(*ast.BasicLit); ok {
					return lit.Value == "0"
				}
			}
		}
	}
	return false
}

// isKeepTTL checks for redis.KeepTTL or a bare KeepTTL identifier.
func isKeepTTL(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "KeepTTL"
	case *ast.Ident:
		return e.Name == "KeepTTL"
	}
	return false
}

// hasExpireNearby checks if there is an Expire/ExpireAt/ExpireNX call within
// withinLines lines after afterLine in the same file.
func hasExpireNearby(file *ast.File, fset *token.FileSet, afterLine int, withinLines int) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !expireMethodNames[sel.Sel.Name] {
			return true
		}
		callLine := fset.Position(call.Pos()).Line
		if callLine > afterLine && callLine <= afterLine+withinLines {
			found = true
			return false
		}
		return true
	})
	return found
}
