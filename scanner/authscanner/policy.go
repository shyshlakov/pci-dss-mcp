package authscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// lenType constants identify how a length check is performed.
const (
	lenTypeBuiltin        = iota // plain len(x)
	lenTypeRuneCount             // utf8.RuneCountInString(x)
	lenTypeRuneConversion        // len([]rune(x))
)

// detectWeakPasswordPolicy detects password length checks that enforce a minimum
// below 12 characters (PCI DSS 8.3.6 requires minimum 12). Also flags use of
// len() (byte count) instead of rune counting for password length.
func detectWeakPasswordPolicy(file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	var findings []scanner.Finding

	ast.Inspect(file, func(n ast.Node) bool {
		binExpr, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}

		lenCall, threshold, op, matched := normalizeLenComparison(binExpr)
		if !matched {
			return true
		}

		if !isPasswordLenCall(lenCall) {
			return true
		}

		lt := lenCallType(lenCall)

		weak := isWeakThreshold(op, threshold)

		if weak {
			pos := fset.Position(binExpr.Pos())
			findings = append(findings, scanner.Finding{
				RuleID:        "AUTH-WEAK-POLICY",
				Severity:      scanner.SeverityCritical,
				RequirementID: "8.3.6",
				FilePath:      path,
				Line:          pos.Line,
				Column:        pos.Column,
				Description:   fmt.Sprintf("Password minimum length check uses threshold %d, PCI DSS v4.0 requires minimum 12 characters", threshold),
				Suggestion:    "Update password policy to require at least 12 characters (PCI DSS 8.3.6).",
			})

			// Additionally flag byte-count len usage for weak password checks.
			// Do NOT flag if using utf8.RuneCountInString or len(rune(...)).
			if lt == lenTypeBuiltin {
				findings = append(findings, scanner.Finding{
					RuleID:        "AUTH-BYTE-COUNT",
					Severity:      scanner.SeverityMedium,
					RequirementID: "8.3.6",
					FilePath:      path,
					Line:          pos.Line,
					Column:        pos.Column,
					Description:   "Password length check uses len() which counts bytes, not characters",
					Suggestion:    "Replace len(password) with utf8.RuneCountInString(password) for correct Unicode character counting.",
				})
			}
		}

		return true
	})

	return findings
}

// normalizeLenComparison extracts a len-like call and integer threshold from a
// BinaryExpr. Returns the call, threshold value, normalized operator (always
// with the len call on the left), and whether the expression matched.
func normalizeLenComparison(expr *ast.BinaryExpr) (lenCall *ast.CallExpr, threshold int64, op token.Token, ok bool) {
	// Try: lenCall OP literal (e.g., len(password) < 8)
	if call, isCall := asLenLikeCall(expr.X); isCall {
		if val, isLit := asIntLit(expr.Y); isLit {
			return call, val, expr.Op, true
		}
	}

	// Try: literal OP lenCall (e.g., 8 > len(password))
	if call, isCall := asLenLikeCall(expr.Y); isCall {
		if val, isLit := asIntLit(expr.X); isLit {
			return call, val, flipOp(expr.Op), true
		}
	}

	return nil, 0, 0, false
}

// asLenLikeCall checks if expr is a len-like call (len() or utf8.RuneCountInString()).
func asLenLikeCall(expr ast.Expr) (*ast.CallExpr, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	if isLenLikeCall(call) {
		return call, true
	}
	return nil, false
}

// asIntLit extracts an integer value from a BasicLit.
func asIntLit(expr ast.Expr) (int64, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	val, err := strconv.ParseInt(lit.Value, 0, 64)
	if err != nil {
		return 0, false
	}
	return val, true
}

// isLenLikeCall returns true if the call is len() or utf8.RuneCountInString().
func isLenLikeCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		// Plain len(x).
		return fn.Name == "len"
	case *ast.SelectorExpr:
		// utf8.RuneCountInString(x).
		if ident, ok := fn.X.(*ast.Ident); ok {
			return ident.Name == "utf8" && fn.Sel.Name == "RuneCountInString"
		}
	}
	return false
}

// lenCallType determines how the length is being calculated.
func lenCallType(call *ast.CallExpr) int {
	// Check for utf8.RuneCountInString().
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "utf8" && sel.Sel.Name == "RuneCountInString" {
				return lenTypeRuneCount
			}
		}
	}

	// Check for len([]rune(x)).
	if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "len" {
		if len(call.Args) == 1 {
			if innerCall, ok := call.Args[0].(*ast.CallExpr); ok {
				if isRuneConversion(innerCall) {
					return lenTypeRuneConversion
				}
			}
		}
	}

	return lenTypeBuiltin
}

// isRuneConversion returns true if the call is a []rune(...) type conversion.
func isRuneConversion(call *ast.CallExpr) bool {
	arrType, ok := call.Fun.(*ast.ArrayType)
	if !ok {
		return false
	}
	// Must be a slice (Len == nil) of rune.
	if arrType.Len != nil {
		return false
	}
	ident, ok := arrType.Elt.(*ast.Ident)
	if !ok {
		return false
	}
	return ident.Name == "rune"
}

// isPasswordLenCall checks if the call's argument references a password-named variable.
func isPasswordLenCall(call *ast.CallExpr) bool {
	// utf8.RuneCountInString(password) -- check the argument.
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "utf8" && sel.Sel.Name == "RuneCountInString" {
				if len(call.Args) == 1 {
					return isPasswordIdent(call.Args[0])
				}
				return false
			}
		}
	}

	// len(x) -- check if x is a password ident, or len([]rune(password)).
	if len(call.Args) == 1 {
		arg := call.Args[0]
		if isPasswordIdent(arg) {
			return true
		}
		// Check for len([]rune(password)).
		if innerCall, ok := arg.(*ast.CallExpr); ok {
			if isRuneConversion(innerCall) && len(innerCall.Args) == 1 {
				return isPasswordIdent(innerCall.Args[0])
			}
		}
	}

	return false
}

// isPasswordIdent checks if an expression is an identifier with a password-related name.
func isPasswordIdent(expr ast.Expr) bool {
	ident, ok := expr.(*ast.Ident)
	if !ok {
		return false
	}
	return isPasswordName(ident.Name)
}

// isWeakThreshold determines if the comparison indicates a password minimum below 12.
//
// After normalization, the comparison is always: len(x) OP threshold.
//
//	token.LSS (<): len(x) < N -> reject if len < N, so min accepted = N. Weak if N < 12.
//	token.LEQ (<=): len(x) <= N -> reject if len <= N, so min accepted = N+1. Weak if N+1 < 12 (i.e., N < 11).
//	token.GTR (>): len(x) > N -> accept if len > N, so min accepted = N+1. Weak if N+1 < 12 (i.e., N < 11).
//	token.GEQ (>=): len(x) >= N -> accept if len >= N, so min accepted = N. Weak if N < 12.
func isWeakThreshold(op token.Token, threshold int64) bool {
	switch op {
	case token.LSS: // len(x) < N
		return threshold < 12
	case token.LEQ: // len(x) <= N
		return threshold < 11
	case token.GTR: // len(x) > N
		return threshold < 11
	case token.GEQ: // len(x) >= N
		return threshold < 12
	}
	return false
}

// flipOp reverses a comparison operator to normalize "literal OP len(x)" to "len(x) flipped(OP) literal".
func flipOp(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.GTR:
		return token.LSS
	case token.LEQ:
		return token.GEQ
	case token.GEQ:
		return token.LEQ
	}
	return op
}
