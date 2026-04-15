package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
)

// CallMatch represents a matched function call in the AST.
type CallMatch struct {
	FuncName string         // e.g., "fmt.Println"
	Position token.Position // file:line:column
	Args     []ast.Expr     // call arguments for further inspection
}

// StringMatch represents a matched string literal in the AST.
type StringMatch struct {
	Value    string // the string value (unquoted)
	Position token.Position
}

// FieldMatch represents a matched struct field in the AST.
type FieldMatch struct {
	Name     string // field name
	TypeExpr string // type as written in source
	Position token.Position
}

// ParseGoFile parses a single Go source file and returns its AST and FileSet.
// Comments are preserved for potential analysis. Returns a descriptive error
// if the file cannot be read or parsed.
func ParseGoFile(path string) (*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f, fset, nil
}

// InspectCalls finds function calls matching any of the given patterns.
// Patterns are in "pkg.Func" format (e.g., "fmt.Println") or plain "Func" format.
func InspectCalls(file *ast.File, fset *token.FileSet, patterns ...string) []CallMatch {
	patternSet := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		patternSet[p] = true
	}

	var matches []CallMatch
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		if name == "" {
			return true
		}
		if patternSet[name] {
			matches = append(matches, CallMatch{
				FuncName: name,
				Position: fset.Position(call.Pos()),
				Args:     call.Args,
			})
		}
		return true
	})
	return matches
}

// InspectStringLiterals finds string literals in the AST that match the given
// regex pattern. The pattern is matched against the unquoted string value.
func InspectStringLiterals(file *ast.File, fset *token.FileSet, pattern *regexp.Regexp) []StringMatch {
	var matches []StringMatch
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val, err := strconv.Unquote(lit.Value)
		if err != nil {
			// Malformed string literal; skip.
			return true
		}
		if pattern.MatchString(val) {
			matches = append(matches, StringMatch{
				Value:    val,
				Position: fset.Position(lit.Pos()),
			})
		}
		return true
	})
	return matches
}

// InspectStructFields finds struct fields whose names satisfy nameMatch.
func InspectStructFields(file *ast.File, fset *token.FileSet, nameMatch func(string) bool) []FieldMatch {
	var matches []FieldMatch
	ast.Inspect(file, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok || st.Fields == nil {
			return true
		}
		for _, field := range st.Fields.List {
			for _, ident := range field.Names {
				if nameMatch(ident.Name) {
					matches = append(matches, FieldMatch{
						Name:     ident.Name,
						TypeExpr: typeString(field.Type),
						Position: fset.Position(ident.Pos()),
					})
				}
			}
		}
		return true
	})
	return matches
}

// callName extracts "pkg.Func" or "Func" from a call expression.
func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		// pkg.Func pattern.
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name + "." + fn.Sel.Name
		}
	case *ast.Ident:
		// Plain Func pattern.
		return fn.Name
	}
	return ""
}

// typeString returns a best-effort string representation of a type expression.
func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name + "." + t.Sel.Name
		}
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.ArrayType:
		if t.Len == nil {
			return "[]" + typeString(t.Elt)
		}
	case *ast.MapType:
		return "map[" + typeString(t.Key) + "]" + typeString(t.Value)
	}
	return fmt.Sprintf("%T", expr)
}
