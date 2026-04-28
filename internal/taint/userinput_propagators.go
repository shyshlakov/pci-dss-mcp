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
	// ReverseFlow indicates source-arg-to-destination propagation: when the
	// source argument is tainted, the destination object referenced by the
	// dst arg (free fn) or the receiver (method) becomes tainted. Used for
	// sink-shaped stdlib helpers like io.Copy / io.WriteString and
	// append-style methods like (*bytes.Buffer).Write*. Default false
	// preserves all existing forward-flow rows.
	ReverseFlow bool
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

	// ---- Plan 21.1-06 (D-07) forward method-projectors ------------------
	// Receiver-to-result flow: when the receiver is USER_INPUT-tainted, the
	// returned value inherits taint. The dispatcher checks SelectorExpr.X
	// taint via isArgTainted on the receiver expression for spec.TypeName!=""
	// rows where no positional arg is tainted.
	//
	// (*url.URL).String INTENTIONALLY ABSENT - engine has no per-field
	// taint state and modeling URL.String as whole-value would conflict
	// with isFrameworkInputFieldRead which already taints URL.RawQuery /
	// URL.RawPath as separate sources. Deferred to a future SSA-based
	// engine.
	//
	// (error).Error INTENTIONALLY ABSENT - builtin interface methods
	// resolve with fn.Pkg() == nil and the dispatcher early-returns at
	// line "fn.Pkg() == nil". httpinputscanner/error_sinks.go covers the
	// dominant slog.Error("k", err.Error()) sink pattern via direct AST
	// shape recognition.
	{PkgPath: "bytes", TypeName: "Buffer", Method: "String"},
	{PkgPath: "bytes", TypeName: "Buffer", Method: "Bytes"},
	{PkgPath: "strings", TypeName: "Builder", Method: "String"},

	// ---- Plan 21.1-07 (D-08+) reverse method-projectors -----------------
	// Source-arg-to-destination flow: when the source argument is tainted,
	// the destination object (passed by pointer for free functions, the
	// receiver for methods) becomes tainted. This closes the io.Copy +
	// (*bytes.Buffer).String() chain where buf would otherwise never become
	// tainted.
	//
	// Free functions: dst is call.Args[0], src is call.Args[1]. The
	// dispatcher derefs &ident shapes to resolve the underlying *types.Var.
	// Other dst shapes (composite literals, function returns) cannot be
	// modeled without SSA and silently no-op (recall-biased acceptable per
	// feedback_scanner_recall_bias).
	//
	// Rune-write methods on Buffer/Builder are intentionally absent -
	// rune-typed args carry no string-shaped leak risk.
	{PkgPath: "io", Method: "Copy", ReverseFlow: true},
	{PkgPath: "io", Method: "CopyN", ReverseFlow: true},
	{PkgPath: "io", Method: "CopyBuffer", ReverseFlow: true},
	{PkgPath: "io", Method: "WriteString", ReverseFlow: true},

	{PkgPath: "bytes", TypeName: "Buffer", Method: "Write", ReverseFlow: true},
	{PkgPath: "bytes", TypeName: "Buffer", Method: "WriteString", ReverseFlow: true},
	{PkgPath: "bytes", TypeName: "Buffer", Method: "WriteByte", ReverseFlow: true},
	{PkgPath: "strings", TypeName: "Builder", Method: "Write", ReverseFlow: true},
	{PkgPath: "strings", TypeName: "Builder", Method: "WriteString", ReverseFlow: true},
	{PkgPath: "strings", TypeName: "Builder", Method: "WriteByte", ReverseFlow: true},
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

		// Plan 21.1-07 reverse-flow: tainted src arg -> tainted dst object.
		// For free functions (TypeName==""), dst is call.Args[0] and src
		// is call.Args[1] (io.Copy/CopyN/CopyBuffer/WriteString all share
		// this shape). For methods (TypeName!=""), dst is the receiver
		// (SelectorExpr.X) and any tainted positional arg triggers
		// propagation.
		if spec.ReverseFlow {
			var dstExpr ast.Expr
			var srcArgs []ast.Expr
			if spec.TypeName != "" {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					dstExpr = sel.X
				}
				srcArgs = call.Args
			} else {
				if len(call.Args) >= 1 {
					dstExpr = call.Args[0]
				}
				if len(call.Args) >= 2 {
					srcArgs = []ast.Expr{call.Args[1]}
				}
			}
			for _, a := range srcArgs {
				if isArgTainted(a, info, state) {
					taintDestObject(dstExpr, info, state)
					return false
				}
			}
			return false
		}

		for _, a := range call.Args {
			if isArgTainted(a, info, state) {
				state.taintedReturns[fn] = true
				return false
			}
		}
		// Plan 21.1-06 forward method-projector: when the spec is keyed by
		// receiver type (TypeName != "") and no positional arg is tainted,
		// also inspect the receiver expression. (*bytes.Buffer).String /
		// .Bytes and (*strings.Builder).String inherit USER_INPUT taint
		// from the receiver, not from the args. The selector form
		// `recv.Method(...)` parses as CallExpr{Fun: SelectorExpr{X: recv}}.
		if spec.TypeName != "" {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if isArgTainted(sel.X, info, state) {
					state.taintedReturns[fn] = true
					return false
				}
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

// taintDestObject marks the *types.Var referenced by dstExpr as tainted in
// flowState. Handles two destination shapes used by io.Copy(&buf, src) and
// (*bytes.Buffer).Write(buf, ...) call sites:
//   - *ast.UnaryExpr{Op: AND, X: *ast.Ident}: deref &ident
//   - *ast.Ident: bare identifier (typed pointer or interface receiver)
//
// Other shapes (composite literals, function returns, selector chains) are
// not modeled - they require SSA-level alias tracking to be sound. Silent
// no-op on unmodeled shapes is recall-biased: misses are acceptable, false
// taints are not. Plan 21.1-07 / D-08+.
func taintDestObject(dstExpr ast.Expr, info *types.Info, state *flowState) {
	if dstExpr == nil || info == nil || state == nil {
		return
	}
	var ident *ast.Ident
	switch x := dstExpr.(type) {
	case *ast.UnaryExpr:
		if x.Op != token.AND {
			return
		}
		if id, ok := x.X.(*ast.Ident); ok {
			ident = id
		}
	case *ast.Ident:
		ident = x
	case *ast.ParenExpr:
		taintDestObject(x.X, info, state)
		return
	}
	if ident == nil {
		return
	}
	obj := info.ObjectOf(ident)
	if obj == nil {
		return
	}
	v, ok := obj.(*types.Var)
	if !ok {
		return
	}
	state.tainted[v] = true
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
