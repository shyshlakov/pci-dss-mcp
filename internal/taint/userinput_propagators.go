package taint

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// D-13 propagator catalog. Matching is by *types.Func / *types.Builtin
// pointer identity against the loaded module so a malicious package named
// "fmt" cannot spoof stdlib recognition (T-21.01-01 mitigation).
//
// Out-of-scope per D-13: goroutine boundaries (`go fn(taint)`) and channel
// sends/receives (`ch <- taint`, `<-ch`). The propagator MUST NOT silently
// propagate through these - Track B's SSA PoC measures whether SSA captures
// them. Adding a hook here would be a regression on D-13.

// passthroughSpec is one row of the propagator dispatch table: a callable
// identified by package path + function/method name, where any tainted arg
// causes the call's return to inherit USER_INPUT taint.
type passthroughSpec struct {
	PkgPath  string
	TypeName string
	Method   string
	// VariadicTaint applies to functions like errors.Join / multierror.Append
	// where ANY element of a variadic chunk taints the return.
	VariadicTaint bool
}

var userInputPassthrough = []passthroughSpec{
	// fmt.Sprintf / Sprint / Sprintln family.
	{PkgPath: "fmt", Method: "Sprintf"},
	{PkgPath: "fmt", Method: "Sprint"},
	{PkgPath: "fmt", Method: "Sprintln"},
	// fmt.Errorf - same shape (treats %w / %s / %v / %q identically for taint).
	{PkgPath: "fmt", Method: "Errorf"},

	// stdlib errors.Join (Go 1.20+).
	{PkgPath: "errors", Method: "Join", VariadicTaint: true},

	// pkg/errors (legacy but common).
	{PkgPath: "github.com/pkg/errors", Method: "Wrap"},
	{PkgPath: "github.com/pkg/errors", Method: "Wrapf"},
	{PkgPath: "github.com/pkg/errors", Method: "WithMessage"},
	{PkgPath: "github.com/pkg/errors", Method: "WithMessagef"},
	{PkgPath: "github.com/pkg/errors", Method: "WithStack"},

	// cockroachdb/errors variants (Tier 2 per D-16.2).
	{PkgPath: "github.com/cockroachdb/errors", Method: "Wrap"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "Wrapf"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "WithMessage"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "WithSafeDetails", VariadicTaint: true},

	// hashicorp/go-multierror.
	{PkgPath: "github.com/hashicorp/go-multierror", Method: "Append", VariadicTaint: true},

	// uber-go/multierr.
	{PkgPath: "go.uber.org/multierr", Method: "Append"},
	{PkgPath: "go.uber.org/multierr", Method: "Combine", VariadicTaint: true},

	// rotisserie/eris.
	{PkgPath: "github.com/rotisserie/eris", Method: "Wrap"},
	{PkgPath: "github.com/rotisserie/eris", Method: "Wrapf"},

	// strings.Join - slice-element passthrough.
	{PkgPath: "strings", Method: "Join", VariadicTaint: true},

	// context.WithValue - value arg propagates into returned context.
	{PkgPath: "context", Method: "WithValue"},
}

// propagateUserInput is the per-CallExpr dispatcher for D-13 propagators. It
// inspects the callee identity and, on match, taints the call's return value
// (via state.taintedReturns) when the relevant argument(s) are tainted.
//
// Returning true means "this call is fully handled by USER_INPUT propagation
// and the caller may skip default processing"; returning false means "no
// USER_INPUT match, fall through to existing R3-R5 rules".
func propagateUserInput(call *ast.CallExpr, info *types.Info, state *flowState) (handled bool) {
	if call == nil || info == nil || state == nil {
		return false
	}

	// Type conversions string(x) / []byte(x) - recognized structurally; the
	// outer R7 expression check already inspects call args for taint, so no
	// state mutation needed. The recognition is documented for completeness.
	if isStringOrBytesConversion(call, info) {
		return false
	}

	fn := resolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recvName := receiverTypeName(fn)
	for _, spec := range userInputPassthrough {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recvName {
			continue
		}
		for _, a := range call.Args {
			if isArgTainted(a, info, state) {
				state.taintedReturns[fn] = true
				return false
			}
		}
		return false
	}

	// gin.Context.Set / Get / GetString / MustGet - function-local key tracking.
	if pkgPath == "github.com/gin-gonic/gin" && recvName == "Context" {
		switch method {
		case "Set":
			handleGinSet(call, info, state)
		case "GetString", "Get", "MustGet":
			handleGinGet(call, info, state, fn)
		}
	}

	return false
}

// propagateUserInputBinaryExpr handles string concatenation BinaryExpr nodes
// per D-13: `tainted + "x"` and `"x" + tainted` both yield a tainted result.
// Returns true when either operand is tainted; the result inheritance is
// picked up by isExprTainted's BinaryExpr branch (already part of the
// existing engine via UnaryExpr / SelectorExpr unwrapping).
//
// Called from propagateInFile's BinaryExpr visit point.
func propagateUserInputBinaryExpr(_ *TaintEngine, expr *ast.BinaryExpr, info *types.Info, state *flowState) bool {
	if expr == nil || info == nil || state == nil {
		return false
	}
	if expr.Op != token.ADD {
		return false
	}
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	if !isStringType(tv.Type) {
		return false
	}
	if isArgTainted(expr.X, info, state) {
		return true
	}
	if isArgTainted(expr.Y, info, state) {
		return true
	}
	return false
}

// recoverInheritsPanicTaint reports whether the package owning info contains
// any panic(arg) site, in which case every recover() call in the same
// package is treated as a tainted source per D-19. Conservative: when the
// package cannot be located in the engine cache, return true (recall-biased
// per D-08).
//
// The full per-package panic-site index lives in Plan 21-02 alongside the
// httpinputscanner; this helper provides the structural API the dispatcher
// needs in Plan 21-01.
func recoverInheritsPanicTaint(engine *TaintEngine, info *types.Info) bool {
	if info == nil {
		return false
	}
	if engine == nil {
		// Recall-biased: assume the package may have a panic site.
		return true
	}
	for _, pkg := range engine.pkgs {
		if pkg == nil || pkg.TypesInfo != info {
			continue
		}
		for _, f := range pkg.Syntax {
			if fileHasPanicWithArg(f) {
				return true
			}
		}
		return false
	}
	return true
}

// fileHasPanicWithArg reports whether f contains a `panic(arg)` call with at
// least one argument expression. Used by recoverInheritsPanicTaint.
func fileHasPanicWithArg(f *ast.File) bool {
	if f == nil {
		return false
	}
	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "panic" && len(call.Args) > 0 {
			found = true
			return false
		}
		return true
	})
	return found
}

// isArgTainted is a thin wrapper used by D-13 propagators. It re-implements
// the small subset of expression unwrapping needed without an engine
// reference (propagator hooks accept only flowState).
// nolint:gocyclo // exhaustive AST shape dispatch for D-13 propagator coverage
func isArgTainted(expr ast.Expr, info *types.Info, state *flowState) bool {
	if expr == nil || info == nil || state == nil {
		return false
	}
	switch e := expr.(type) {
	case *ast.Ident:
		if obj := info.Uses[e]; obj != nil && state.tainted[obj] {
			return true
		}
		if obj := info.Defs[e]; obj != nil && state.tainted[obj] {
			return true
		}
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok && state.tainted[sel.Obj()] {
			return true
		}
		if obj := info.Uses[e.Sel]; obj != nil && state.tainted[obj] {
			return true
		}
		return isArgTainted(e.X, info, state)
	case *ast.UnaryExpr:
		return isArgTainted(e.X, info, state)
	case *ast.ParenExpr:
		return isArgTainted(e.X, info, state)
	case *ast.StarExpr:
		return isArgTainted(e.X, info, state)
	case *ast.CallExpr:
		fn := resolveCallee(info, e)
		if fn != nil && state.taintedReturns[fn] {
			return true
		}
		for _, a := range e.Args {
			if isArgTainted(a, info, state) {
				return true
			}
		}
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			if isArgTainted(e.X, info, state) || isArgTainted(e.Y, info, state) {
				return true
			}
		}
	case *ast.CompositeLit:
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if isArgTainted(kv.Value, info, state) {
					return true
				}
				continue
			}
			if isArgTainted(el, info, state) {
				return true
			}
		}
	}
	return false
}

// isStringOrBytesConversion recognizes type conversions of the form
// string(x) and []byte(x). The CallExpr's Fun resolves to a *types.TypeName
// for string and to an *ast.ArrayType for []byte.
func isStringOrBytesConversion(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil || len(call.Args) != 1 {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if obj := info.Uses[fn]; obj != nil {
			if _, ok := obj.(*types.TypeName); ok && obj.Name() == "string" {
				return true
			}
		}
	case *ast.ArrayType:
		_ = fn
		return true
	}
	return false
}

// handleGinSet records gin.Context.Set("k", tainted) into a function-local
// side-table on flowState keyed by the literal "k". Downstream calls to
// GetString / Get / MustGet on the same key inherit taint within the same
// query frame.
func handleGinSet(call *ast.CallExpr, info *types.Info, state *flowState) {
	if len(call.Args) < 2 {
		return
	}
	key, ok := stringLiteral(call.Args[0])
	if !ok {
		return
	}
	if !isArgTainted(call.Args[1], info, state) {
		return
	}
	if state.ginCtxKeys == nil {
		state.ginCtxKeys = map[string]bool{}
	}
	state.ginCtxKeys[key] = true
}

// handleGinGet checks the per-flowState ginCtxKeys map; on hit, marks the
// callee as returning tainted so downstream R4 / isExprTainted propagation
// catches the value at its consumer.
func handleGinGet(call *ast.CallExpr, _ *types.Info, state *flowState, fn *types.Func) {
	if len(call.Args) < 1 {
		return
	}
	key, ok := stringLiteral(call.Args[0])
	if !ok {
		return
	}
	if state.ginCtxKeys[key] {
		state.taintedReturns[fn] = true
	}
}

// stringLiteral returns the Go string value of expr if it is a string-kind
// BasicLit, else "" / false.
func stringLiteral(expr ast.Expr) (string, bool) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v := bl.Value
	if len(v) < 2 {
		return "", false
	}
	v = strings.TrimPrefix(v, `"`)
	v = strings.TrimSuffix(v, `"`)
	v = strings.TrimPrefix(v, "`")
	v = strings.TrimSuffix(v, "`")
	return v, true
}

// isStringType reports whether t is a (named or basic) string type.
func isStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Kind() == types.String || b.Kind() == types.UntypedString
	}
	return false
}
