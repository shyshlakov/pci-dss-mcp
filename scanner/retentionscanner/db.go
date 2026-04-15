package retentionscanner

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// sqlExecMethods are database methods that execute raw SQL.
var sqlExecMethods = map[string]bool{
	"Exec":      true,
	"NamedExec": true,
}

// gormStoreMethods are ORM methods that persist data.
var gormStoreMethods = map[string]bool{
	"Create": true,
	"Save":   true,
}

// detectDBStorageOfSensitiveData walks the AST for SQL INSERT and gorm
// Create/Save calls involving sensitive data.
func detectDBStorageOfSensitiveData(file *ast.File, fset *token.FileSet, filePath string, aliases map[string]string) []scanner.Finding {
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
		pos := fset.Position(call.Pos())

		// Check SQL Exec/NamedExec for INSERT with sensitive data.
		if sqlExecMethods[methodName] {
			if f := checkSQLExec(call, pos, filePath); f != nil {
				findings = append(findings, *f)
			}
			return true
		}

		// Check gorm Create/Save with sensitive data.
		if gormStoreMethods[methodName] {
			if f := checkGormStore(call, pos, filePath, methodName); f != nil {
				findings = append(findings, *f)
			}
			return true
		}

		return true
	})

	return findings
}

// checkSQLExec checks if a db.Exec call is an INSERT with sensitive data args.
func checkSQLExec(call *ast.CallExpr, pos token.Position, filePath string) *scanner.Finding {
	if len(call.Args) < 1 {
		return nil
	}

	// Check if the SQL query is an INSERT.
	firstArg := call.Args[0]
	if !isSQLInsert(firstArg) {
		return nil
	}

	// Check if any subsequent arguments contain sensitive data.
	hasSensitive := false
	for _, arg := range call.Args[1:] {
		if isSensitiveExpr(arg) {
			hasSensitive = true
			break
		}
	}
	if !hasSensitive {
		return nil
	}

	return &scanner.Finding{
		RuleID:        "RET-DB-SENSITIVE-STORE",
		Severity:      scanner.SeverityCritical,
		RequirementID: "3.2.1",
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description: "Sensitive data stored in persistent database without automatic expiry. " +
			"PCI DSS 3.2.1 prohibits storing SAD after authorization.",
		Suggestion: "Use time-limited storage or ensure data is purged after authorization.",
	}
}

// checkGormStore checks if a gorm Create/Save call involves sensitive data.
func checkGormStore(call *ast.CallExpr, pos token.Position, filePath string, methodName string) *scanner.Finding {
	if len(call.Args) < 1 {
		return nil
	}

	// Check if the argument involves sensitive data.
	hasSensitive := false
	for _, arg := range call.Args {
		if isSensitiveExpr(arg) {
			hasSensitive = true
			break
		}
	}
	if !hasSensitive {
		return nil
	}

	return &scanner.Finding{
		RuleID:        "RET-GORM-SENSITIVE-STORE",
		Severity:      scanner.SeverityCritical,
		RequirementID: "3.2.1",
		FilePath:      filePath,
		Line:          pos.Line,
		Column:        pos.Column,
		Description: "Sensitive data stored via ORM " + methodName + " without automatic expiry. " +
			"PCI DSS 3.2.1 prohibits storing SAD after authorization.",
		Suggestion: "Use time-limited storage or ensure data is purged after authorization.",
	}
}

// isSQLInsert checks if the expression is a string literal containing "INSERT"
// (case-insensitive).
func isSQLInsert(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	val, err := strconv.Unquote(lit.Value)
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToUpper(val), "INSERT")
}
