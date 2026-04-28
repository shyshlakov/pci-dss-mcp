package taint

// USER_INPUT taint kind is additive in the public taint API per CONTEXT.md D-09;
// existing PAN/CVV/SAD logic remains untouched. The TaintUserInput SinkKind
// constant is declared in sinks.go alongside the other kinds.

import (
	"go/ast"
	"go/types"
)

// UserInputSource identifies a single framework HTTP input accessor whose
// return value (or by-pointer struct argument fields, for body decoders)
// carries USER_INPUT taint. The fields are populated from a baked-in framework
// recognition list (gin, chi, gorilla/mux, net/http, echo, fiber, validator),
// resolved against the loaded module's type information at query time.
//
// The struct is comparable so callers can build it directly without
// reflection. A zero-value UserInputSource is safe and resolves to nothing.
type UserInputSource struct {
	// Package is the canonical import path of the framework package
	// (e.g. "github.com/gin-gonic/gin", "net/http").
	Package string
	// TypeName is the receiver type's unqualified name for method calls
	// (e.g. "Context", "Request"). Empty for free functions.
	TypeName string
	// Method is the method or free-function name (e.g. "Param", "URLParam").
	Method string
	// Framework is a short hint string useful for debugging and
	// downstream emission (e.g. "gin", "chi", "mux", "net/http").
	Framework string
	// IsBodyDecoder marks ShouldBindJSON-shape sources whose first
	// by-pointer struct argument's fields become tainted after the call.
	IsBodyDecoder bool
}

// FlowsToUserInput reports whether a USER_INPUT-tainted value originating at
// src reaches any sink matching sinkPattern in the loaded module. The signature
// mirrors FlowsTo, returning false for any nil/unloaded/unresolved condition
// rather than an error.
//
// In Plan 21-01 the propagator hook is a no-op; the source recognition path
// in Task 2 and the propagator catalog in Task 3 fill it in. Until those
// land, FlowsToUserInput safely returns false for any caller.
func (e *TaintEngine) FlowsToUserInput(src UserInputSource, sinkPattern SinkPattern) bool {
	if e == nil || !e.loadOK {
		return false
	}
	if src.Package == "" || src.Method == "" {
		return false
	}
	if e.lookupUserInputFunc(src) == nil {
		return false
	}
	targets := e.resolveSinks(sinkPattern)
	if len(targets) == 0 {
		return false
	}
	// Forward worklist seeded from the user-input call site is wired in
	// Tasks 2/3. The Plan 21-01 contract is that the API exists, returns
	// false on unresolved sources, and does not break existing flows.
	return false
}

// lookupUserInputFunc resolves a UserInputSource to its concrete *types.Func
// in the loaded module by walking the receiver type's pointer method set
// (matching the resolveSinks pattern). Returns nil when the package, type, or
// method is missing from the loaded graph.
//
// For free functions (TypeName=""), the lookup falls back to the package's
// scope.
func (e *TaintEngine) lookupUserInputFunc(src UserInputSource) *types.Func {
	if e == nil || src.Package == "" || src.Method == "" {
		return nil
	}
	pkg := findLoadedPackage(e.pkgs, src.Package)
	if pkg == nil || pkg.Types == nil {
		return nil
	}
	if src.TypeName == "" {
		obj := pkg.Types.Scope().Lookup(src.Method)
		if fn, ok := obj.(*types.Func); ok {
			return fn
		}
		return nil
	}
	obj := pkg.Types.Scope().Lookup(src.TypeName)
	if obj == nil {
		return nil
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return nil
	}
	mset := types.NewMethodSet(types.NewPointer(named))
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		fn, ok := sel.Obj().(*types.Func)
		if !ok {
			continue
		}
		if fn.Name() == src.Method {
			return fn
		}
	}
	if iface, ok := named.Underlying().(*types.Interface); ok {
		for i := 0; i < iface.NumMethods(); i++ {
			fn := iface.Method(i)
			if fn.Name() == src.Method {
				return fn
			}
		}
	}
	return nil
}

// propagateUserInputCall is the per-CallExpr hook invoked from
// propagateInFile. It seeds USER_INPUT taint at recognized framework input
// accessors (Task 2) and applies D-13 propagator rules (Task 3). Returning
// true means "fully handled, skip default processing"; returning false means
// "no USER_INPUT handling applied, continue with default rules".
//
// In Plan 21-01 we always return false so existing PAN/CVV/SAD propagation
// still runs alongside USER_INPUT seeding — both kinds share the same
// state.tainted map and that is intentional for Plan 21-02 sink integration.
func (e *TaintEngine) propagateUserInputCall(call *ast.CallExpr, info *types.Info, state *flowState) (handled bool) {
	if call == nil || info == nil || state == nil {
		return false
	}
	src, ok := isFrameworkInputSource(call, info)
	if !ok {
		// Task 3 propagator catalog is a no-op until Task 3 commits.
		return propagateUserInput(call, info, state)
	}
	if src.IsBodyDecoder {
		seedBodyDecoderFields(call, info, state)
		return false
	}
	seedCallReturn(call, info, state)
	return false
}

// seedCallReturn marks the call expression's result type as USER_INPUT-tainted.
// We do this by tainting the *ast.CallExpr-bound Type info via state.tainted
// keyed on the synthetic "call result" — but state.tainted keys are
// types.Object, so we approximate by tainting the receiver of any LHS that
// consumes this call (handled by R1) AND by setting the callee in
// taintedReturns so isExprTainted picks it up via R4.
func seedCallReturn(call *ast.CallExpr, info *types.Info, state *flowState) {
	fn := resolveCallee(info, call)
	if fn == nil {
		return
	}
	state.taintedReturns[fn] = true
}

// seedBodyDecoderFields handles ShouldBindJSON-shape body decoders: the first
// argument is by-pointer to a user struct; every field of that struct
// becomes USER_INPUT-tainted after the call.
func seedBodyDecoderFields(call *ast.CallExpr, info *types.Info, state *flowState) {
	if len(call.Args) == 0 {
		return
	}
	arg := call.Args[0]
	// Unwrap & if present.
	if u, ok := arg.(*ast.UnaryExpr); ok {
		arg = u.X
	}
	tv, ok := info.Types[arg]
	if !ok {
		return
	}
	t := tv.Type
	if t == nil {
		return
	}
	// Dereference pointer wrappers — body decoders commonly receive *T.
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		return
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if f == nil {
			continue
		}
		state.tainted[f] = true
		state.depth[f] = 0
	}
}
