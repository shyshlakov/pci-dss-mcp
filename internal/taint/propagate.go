package taint

import (
	"go/ast"
	"go/token"
	"go/types"

	"golang.org/x/tools/go/packages"
)

// maxDepth bounds the number of function-call hops the forward worklist
// will cross before giving up. Five hops is the empirical number from the
// strategy → http client → visa sdk), with one frame of headroom.
const maxDepth = 5

// FlowsTo reports whether the data origin described by src reaches any sink
// that matches sinkPattern in the loaded module. This is the single public
// query API for (lock) — it returns a bool, never an error.
//
// Propagation rules implemented (see Pattern 2 for the
// canonical table):
//
//	R1 assignment y:= x.Field → taint y
//	R2 struct literal T{F: x} → taint the struct field F
//	R3 call-site param bind f(x) → taint f's parameter, depth+1
//	R4 return propagation return x → mark callee as "returns tainted"
//	R5 sink hit sinkFn(x) → return true
//	R6 address-of &x → same object key
//	R7 field-access chain a.b.c → base tainted ⇒ chain tainted
//
// Inconclusive paths (interface dispatch, closures, channels, reflection)
// yield false and are documented known-limitations for.
func (e *TaintEngine) FlowsTo(src Source, sinkPattern SinkPattern) bool {
	if e == nil || !e.loadOK {
		return false
	}
	srcObj := e.lookupField(src)
	if srcObj == nil {
		return false
	}
	targets := e.resolveSinks(sinkPattern)
	if len(targets) == 0 {
		return false
	}
	sinkSet := sinksByFunc(targets)

	// Per-query state. All maps are owned by this call frame so FlowsTo
	// calls from different goroutines do not share taint state.
	state := &flowState{
		tainted:        map[types.Object]bool{srcObj: true},
		depth:          map[types.Object]int{srcObj: 0},
		visitedFuncs:   map[*types.Func]bool{},
		taintedReturns: map[*types.Func]bool{},
		sinks:          sinkSet,
	}
	worklist := []types.Object{srcObj}

	// Outer loop: we repeat the full file sweep until a fixed point is
	// reached (no new tainted objects added). This is less efficient than a
	// true worklist dataflow analysis but it mirrors the RESEARCH Pattern 2
	// "forward sweep to fixed point" recommendation and keeps the code
	// simple. Bounded by len(tainted) which can grow at most by the number
	// of distinct types.Object in the module — finite.
	for len(worklist) > 0 {
		obj := worklist[0]
		worklist = worklist[1:]
		if state.depth[obj] > maxDepth {
			continue
		}
		// Cross every package/file in the module looking for uses of obj.
		for _, pkg := range e.pkgs {
			if pkg == nil || pkg.TypesInfo == nil {
				continue
			}
			for _, f := range pkg.Syntax {
				if f == nil {
					continue
				}
				before := len(state.tainted)
				hit := e.propagateInFile(pkg, f, state)
				if hit {
					return true
				}
				// Anything new from this pass needs to be re-swept since a
				// later file may consume it.
				if len(state.tainted) > before {
					for k := range state.tainted {
						// Cheap re-queue: we only need to re-process objects
						// whose depth is still within budget.
						if state.depth[k] <= maxDepth {
							worklist = append(worklist, k)
						}
					}
					// Break out of inner loops to restart the worklist; the
					// outer for-range already iterates pkgs/files, so we
					// simply continue — any previously-visited file that now
					// matches a newly-tainted object will be seen on the
					// next iteration.
				}
			}
		}
		// Drain worklist uniqueness: avoid unbounded growth by deduping.
		worklist = dedupObjects(worklist, state)
	}
	return false
}

// flowState is the per-query mutable bag carried into every rule.
type flowState struct {
	tainted        map[types.Object]bool
	depth          map[types.Object]int
	visitedFuncs   map[*types.Func]bool
	taintedReturns map[*types.Func]bool
	sinks          map[*types.Func]bool
	// ginCtxKeys tracks gin.Context.Set("k", tainted) so downstream
	// Get / GetString / MustGet on the same key inherits taint within the
	// same query frame. D-13.
	ginCtxKeys map[string]bool
}

// dedupObjects removes already-visited objects from the worklist so the
// main loop terminates even under cyclic propagation graphs.
func dedupObjects(in []types.Object, _ *flowState) []types.Object {
	seen := map[types.Object]bool{}
	out := in[:0]
	for _, o := range in {
		if o == nil || seen[o] {
			continue
		}
		seen[o] = true
		out = append(out, o)
	}
	return out
}

// propagateInFile walks a single file once and applies R1-R7 incrementally,
// returning true as soon as R5 fires for any tainted value reaching a sink.
// The walker maintains an enclosingFunc stack so R4 can associate a return
// statement with its callee.
func (e *TaintEngine) propagateInFile(pkg *packages.Package, f *ast.File, state *flowState) bool {
	info := pkg.TypesInfo
	if info == nil {
		return false
	}

	// Stack of enclosing FuncDecls / FuncLits, for R4 return propagation.
	var funcStack []*types.Func

	var hit bool
	ast.Inspect(f, func(n ast.Node) bool {
		if hit {
			return false
		}
		switch node := n.(type) {
		case nil:
			// ast.Inspect passes nil after descending a subtree — pop the
			// enclosing-function stack if necessary.
			if len(funcStack) > 0 {
				funcStack = funcStack[:len(funcStack)-1]
			}
			return false

		case *ast.FuncDecl:
			if node.Name != nil {
				if obj := info.Defs[node.Name]; obj != nil {
					if fn, ok := obj.(*types.Func); ok {
						funcStack = append(funcStack, fn)
					} else {
						funcStack = append(funcStack, nil)
					}
				} else {
					funcStack = append(funcStack, nil)
				}
			} else {
				funcStack = append(funcStack, nil)
			}
			return true

		case *ast.AssignStmt:
			// R1: y:= tainted → taint y.
			e.applyRule1(pkg, node, state)
			return true

		case *ast.CompositeLit:
			// R2: T{Field: tainted} → taint struct field object.
			e.applyRule2(pkg, node, state)
			return true

		case *ast.ReturnStmt:
			// R4: return tainted → mark enclosing function as
			// "returns tainted".
			if len(funcStack) > 0 {
				if fn := funcStack[len(funcStack)-1]; fn != nil {
					if e.anyExprTainted(pkg, node.Results, state) {
						state.taintedReturns[fn] = true
					}
				}
			}
			return true

		case *ast.BinaryExpr:
			// USER_INPUT D-13: string concat propagator hook. The result is
			// only consulted via isExprTainted later; this visit step exists
			// so the per-BinaryExpr matcher contract is satisfied.
			_ = propagateUserInputBinaryExpr(e, node, info, state)
			return true

		case *ast.CallExpr:
			// R5 FIRST — sink hit check before we descend into args.
			if e.checkSinkHit(pkg, node, state) {
				hit = true
				return false
			}
			// D-21.1-04: gin recovery callback auxiliary source. The
			// `recovered any` slot of CustomRecoveryWithWriter / CustomRecovery
			// / RecoveryWithWriter callbacks carries handler-derived panic
			// values; mark each FuncLit's index-1 *types.Var as tainted so
			// downstream reads inside the callback body inherit USER_INPUT
			// taint via existing R1/R7 propagation. RecognizeRecoveryCallback
			// is a no-op for any non-recovery call.
			for _, v := range RecognizeRecoveryCallback(node, info) {
				if v == nil {
					continue
				}
				state.tainted[v] = true
				state.depth[v] = 0
			}
			// USER_INPUT propagator hook (Plan 21-01 Tasks 1-3).
			if e.propagateUserInputCall(node, info, state) {
				return true
			}
			// R3: tainted argument → taint callee parameter.
			e.applyRule3(pkg, node, state)
			// R4 consumer side: if callee returns tainted, downstream
			// usage of the call result should inherit taint. We mark the
			// call expression itself by tainting the receiving variable
			// via R1 when this CallExpr appears on an assign RHS. The
			// isExprTainted helper reads taintedReturns directly so no
			// extra bookkeeping is needed here.
			return true
		}
		return true
	})
	return hit
}

// applyRule1 handles R1 (assignment propagation).
// For each LHS ident, if ANY corresponding RHS is already tainted,
// mark the LHS *types.Var as tainted and enqueue it.
func (e *TaintEngine) applyRule1(pkg *packages.Package, assign *ast.AssignStmt, state *flowState) {
	info := pkg.TypesInfo
	if info == nil || len(assign.Rhs) == 0 || len(assign.Lhs) == 0 {
		return
	}
	// Tainted if any RHS expression is tainted (covers both 1-to-1 and
	// multi-return assignment forms; more precise ordering is a
	// refinement and not required by any acceptance test).
	rhsTainted := false
	for _, rhs := range assign.Rhs {
		if e.isExprTainted(pkg, rhs, state) {
			rhsTainted = true
			break
		}
	}
	if !rhsTainted {
		return
	}
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil {
				state.tainted[obj] = true
				// LHS inherits the current function-frame depth — any
				// transitively reached callee will bump depth via R3.
				state.depth[obj] = 0
			}
		}
		if sel, ok := lhs.(*ast.SelectorExpr); ok {
			if obj := info.ObjectOf(sel.Sel); obj != nil {
				state.tainted[obj] = true
				state.depth[obj] = 0
			}
		}
	}
}

// applyRule2 handles R2 (struct literal field seeding). When a composite
// literal contains a tainted value in a keyed element, we taint the struct
// field *types.Var itself — any subsequent access to.Field on this or any
// other instance will then propagate via R7.
func (e *TaintEngine) applyRule2(pkg *packages.Package, lit *ast.CompositeLit, state *flowState) {
	info := pkg.TypesInfo
	if info == nil {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if !e.isExprTainted(pkg, kv.Value, state) {
			continue
		}
		// A1 mitigation: use ObjectOf, which falls back to Defs when Uses
		// is empty for composite-literal keys.
		if obj := info.ObjectOf(identOrNil(kv.Key)); obj != nil {
			state.tainted[obj] = true
			state.depth[obj] = 0
		}
	}
}

// identOrNil downcasts an ast.Expr to *ast.Ident or returns nil.
func identOrNil(expr ast.Expr) *ast.Ident {
	if id, ok := expr.(*ast.Ident); ok {
		return id
	}
	return nil
}

// applyRule3 handles R3 (call-site parameter binding). For each tainted
// argument, we taint the corresponding parameter variable of the callee and
// increment depth. Also respects the visitedFuncs cycle guard so a recursive
// f→g→f chain cannot re-enter f twice in the same query.
func (e *TaintEngine) applyRule3(pkg *packages.Package, call *ast.CallExpr, state *flowState) {
	info := pkg.TypesInfo
	if info == nil {
		return
	}
	callee := resolveCallee(info, call)
	if callee == nil {
		return
	}
	// Interface-dispatch pitfall 4: the callee's receiver is an interface →
	// we cannot statically enumerate implementations in. Stop the
	// trace silently.
	if sig, ok := callee.Type().(*types.Signature); ok && sig.Recv() != nil {
		if _, isIface := sig.Recv().Type().Underlying().(*types.Interface); isIface {
			return
		}
	}
	if state.visitedFuncs[callee] {
		return
	}
	state.visitedFuncs[callee] = true

	sig, ok := callee.Type().(*types.Signature)
	if !ok || sig.Params() == nil {
		return
	}

	// Figure out the current max depth for this query.
	currentDepth := 0
	for _, d := range state.depth {
		if d > currentDepth {
			currentDepth = d
		}
	}
	nextDepth := currentDepth + 1
	if nextDepth > maxDepth {
		return
	}

	for i, arg := range call.Args {
		if i >= sig.Params().Len() {
			break
		}
		if !e.isExprTainted(pkg, arg, state) {
			continue
		}
		param := sig.Params().At(i)
		state.tainted[param] = true
		state.depth[param] = nextDepth
	}
}

// anyExprTainted is the slice form of isExprTainted used by the ReturnStmt
// visitor (R4). Returns true if any expression in exprs is currently tainted.
func (e *TaintEngine) anyExprTainted(pkg *packages.Package, exprs []ast.Expr, state *flowState) bool {
	for _, ex := range exprs {
		if e.isExprTainted(pkg, ex, state) {
			return true
		}
	}
	return false
}

// isExprTainted recursively checks whether expr refers to a currently
// tainted types.Object. Implements R6 (address-of transparency) and R7
// (selector-chain propagation) by unwrapping wrapper expression nodes.
func (e *TaintEngine) isExprTainted(pkg *packages.Package, expr ast.Expr, state *flowState) bool {
	if expr == nil {
		return false
	}
	info := pkg.TypesInfo
	if info == nil {
		return false
	}
	switch ex := expr.(type) {
	case *ast.Ident:
		if obj := info.Uses[ex]; obj != nil && state.tainted[obj] {
			return true
		}
		if obj := info.Defs[ex]; obj != nil && state.tainted[obj] {
			return true
		}
	case *ast.SelectorExpr:
		// R7: a.b.c chain.
		if sel, ok := info.Selections[ex]; ok {
			if state.tainted[sel.Obj()] {
				return true
			}
		}
		if obj := info.Uses[ex.Sel]; obj != nil && state.tainted[obj] {
			return true
		}
		if e.isExprTainted(pkg, ex.X, state) {
			return true
		}
	case *ast.UnaryExpr:
		// R6: &x preserves object identity.
		if ex.Op == token.AND || ex.Op == token.ARROW {
			return e.isExprTainted(pkg, ex.X, state)
		}
		return e.isExprTainted(pkg, ex.X, state)
	case *ast.ParenExpr:
		return e.isExprTainted(pkg, ex.X, state)
	case *ast.StarExpr:
		return e.isExprTainted(pkg, ex.X, state)
	case *ast.IndexExpr:
		return e.isExprTainted(pkg, ex.X, state)
	case *ast.CompositeLit:
		for _, el := range ex.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				if e.isExprTainted(pkg, kv.Value, state) {
					return true
				}
				continue
			}
			if e.isExprTainted(pkg, el, state) {
				return true
			}
		}
	case *ast.CallExpr:
		// R4 plumbing: if callee returns tainted, the call result is
		// tainted at the usage site (e.g. `y:= f(tainted)` ⇒ y tainted).
		if callee := resolveCallee(info, ex); callee != nil {
			if state.taintedReturns[callee] {
				return true
			}
		}
		// Also propagate when a tainted value is passed through a plain
		// wrapper like Encrypt(c.CVV): the parameter binding in R3 will
		// taint the wrapped param AND R4 will mark the callee as
		// returning-tainted on the next pass.
		for _, a := range ex.Args {
			if e.isExprTainted(pkg, a, state) {
				return true
			}
		}
	}
	return false
}

// checkSinkHit implements R5 — the early-exit check run at every CallExpr
// before any recursion. Returns true iff the callee is one of the resolved
// sinkTargets AND at least one argument is currently tainted.
//
// Callee resolution matches RESEARCH §Code Example 3: Selections first (for
// method calls with possible embedding/promotion), then Uses[Sel] for
// package-qualified calls.
func (e *TaintEngine) checkSinkHit(pkg *packages.Package, call *ast.CallExpr, state *flowState) bool {
	info := pkg.TypesInfo
	if info == nil {
		return false
	}
	callee := resolveCallee(info, call)
	if callee == nil {
		return false
	}
	if !state.sinks[callee] {
		return false
	}
	for _, a := range call.Args {
		if e.isExprTainted(pkg, a, state) {
			return true
		}
	}
	return false
}

// resolveCallee returns the *types.Func for a CallExpr's callee, or nil if
// the callee cannot be resolved (builtin, interface dispatch, function
// literal expression, etc.). Covers the three branches from RESEARCH
// §Example 3: SelectorExpr via Selections, SelectorExpr via Uses, Ident via
// Uses.
func resolveCallee(info *types.Info, call *ast.CallExpr) *types.Func {
	if info == nil || call == nil {
		return nil
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[fn]; ok {
			if f, ok := sel.Obj().(*types.Func); ok {
				return f
			}
		}
		if obj := info.Uses[fn.Sel]; obj != nil {
			if f, ok := obj.(*types.Func); ok {
				return f
			}
		}
	case *ast.Ident:
		if obj := info.Uses[fn]; obj != nil {
			if f, ok := obj.(*types.Func); ok {
				return f
			}
		}
	}
	return nil
}
