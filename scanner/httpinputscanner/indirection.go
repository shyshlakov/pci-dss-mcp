package httpinputscanner

import (
	"go/ast"
	"go/types"
)

// loggerInterfaceTypes lists the canonical Tier-1 logger types per D-16.1.
// Used by isContextExtractedLogger to recognize the return type of a context
// extractor and by directLoggerErrorReceiver to recognize logger Error
// receivers.
var loggerInterfaceTypes = []struct {
	pkg  string
	name string
}{
	{pkg: "log/slog", name: "Logger"},
	{pkg: "github.com/sirupsen/logrus", name: "Logger"},
	{pkg: "github.com/sirupsen/logrus", name: "Entry"},
	{pkg: "go.uber.org/zap", name: "Logger"},
	{pkg: "go.uber.org/zap", name: "SugaredLogger"},
	{pkg: "github.com/rs/zerolog", name: "Logger"},
	{pkg: "github.com/go-logr/logr", name: "Logger"},
	{pkg: "github.com/hashicorp/go-hclog", name: "Logger"},
	{pkg: "k8s.io/klog/v2", name: "Logger"},
}

// isCentralizedAbortHelper applies the D-14 heuristic: a function is a
// centralized abort helper when it has at least one error parameter AND its
// body contains a known log sink call AND that error parameter (or one of
// them) appears as an argument to the log call. The third condition rejects
// the Vault-style "logs only own-derived state" negative case.
//
// fn is the resolved *types.Func for the FuncDecl. file is the *ast.File the
// FuncDecl lives in (used to locate the FuncDecl body). info is the package
// types.Info for the file.
func isCentralizedAbortHelper(fn *types.Func, file *ast.File, info *types.Info) bool {
	if fn == nil || file == nil || info == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Params() == nil {
		return false
	}
	if !signatureHasErrorParam(sig) {
		return false
	}
	decl := findFuncDecl(file, fn)
	if decl == nil || decl.Body == nil {
		return false
	}
	errParams := errorParamObjects(decl, info)
	if len(errParams) == 0 {
		return false
	}
	var hasLogCall bool
	var errFlowsToLog bool
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if _, ok := isLogSink(call, info); !ok {
			if _, ok := isErrorSink(call, info); !ok {
				return true
			}
		}
		hasLogCall = true
		if callArgsReferenceErrParam(call, errParams, info) {
			errFlowsToLog = true
		}
		return true
	})
	if !hasLogCall {
		return false
	}
	return errFlowsToLog
}

// isContextExtractedLogger applies the D-14 / D-16.4 heuristic: a function is
// a context-extracted logger when it takes context.Context as a parameter and
// returns a logger-shaped value. Logger-shaped per D-16.1 Tier-1 list.
func isContextExtractedLogger(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	if !signatureHasContextParam(sig) {
		return false
	}
	if !signatureReturnsLoggerType(sig) {
		return false
	}
	return true
}

// signatureHasErrorParam reports whether sig has at least one parameter whose
// type is the built-in error interface.
func signatureHasErrorParam(sig *types.Signature) bool {
	if sig == nil || sig.Params() == nil {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if isBuiltinErrorType(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// signatureHasContextParam reports whether sig has at least one parameter of
// type context.Context.
func signatureHasContextParam(sig *types.Signature) bool {
	if sig == nil || sig.Params() == nil {
		return false
	}
	for i := 0; i < sig.Params().Len(); i++ {
		if isContextContextType(sig.Params().At(i).Type()) {
			return true
		}
	}
	return false
}

// signatureReturnsLoggerType reports whether sig has at least one return value
// whose type matches one of the recognized logger types in loggerInterfaceTypes.
func signatureReturnsLoggerType(sig *types.Signature) bool {
	if sig == nil || sig.Results() == nil {
		return false
	}
	for i := 0; i < sig.Results().Len(); i++ {
		if isLoggerInterfaceType(sig.Results().At(i).Type()) {
			return true
		}
	}
	return false
}

// isBuiltinErrorType reports whether t is the built-in error interface.
func isBuiltinErrorType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil {
		return false
	}
	if obj.Name() != "error" {
		return false
	}
	return obj.Pkg() == nil
}

// isContextContextType reports whether t is context.Context.
func isContextContextType(t types.Type) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == "context" && obj.Name() == "Context"
}

// isLoggerInterfaceType reports whether t resolves (with optional pointer
// indirection) to one of the recognized logger types.
func isLoggerInterfaceType(t types.Type) bool {
	if t == nil {
		return false
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	for _, l := range loggerInterfaceTypes {
		if obj.Pkg().Path() == l.pkg && obj.Name() == l.name {
			return true
		}
	}
	return false
}

// findFuncDecl locates the *ast.FuncDecl whose name resolves to fn within
// file.
func findFuncDecl(file *ast.File, fn *types.Func) *ast.FuncDecl {
	if file == nil || fn == nil {
		return nil
	}
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name == nil {
			continue
		}
		if fd.Name.Name == fn.Name() {
			return fd
		}
	}
	return nil
}

// errorParamObjects walks decl.Type.Params and returns the *types.Var objects
// for parameters whose declared type is the built-in error interface.
func errorParamObjects(decl *ast.FuncDecl, info *types.Info) []*types.Var {
	var out []*types.Var
	if decl == nil || decl.Type == nil || decl.Type.Params == nil {
		return out
	}
	for _, field := range decl.Type.Params.List {
		tv, ok := info.Types[field.Type]
		if !ok || !isBuiltinErrorType(tv.Type) {
			continue
		}
		for _, name := range field.Names {
			if obj, _ := info.Defs[name].(*types.Var); obj != nil {
				out = append(out, obj)
			}
		}
	}
	return out
}

// callArgsReferenceErrParam reports whether any argument of call (recursively,
// looking inside attribute-builder calls and method calls) references one of
// the err parameter objects either directly (`err`) or via `err.Error()` or
// `fmt.Errorf("...: %w", err)` chain.
func callArgsReferenceErrParam(call *ast.CallExpr, errParams []*types.Var, info *types.Info) bool {
	if call == nil {
		return false
	}
	for _, a := range call.Args {
		if exprReferencesErrParam(a, errParams, info) {
			return true
		}
	}
	return false
}

// exprReferencesErrParam recursively walks expr looking for a reference to
// any object in errParams.
func exprReferencesErrParam(expr ast.Expr, errParams []*types.Var, info *types.Info) bool {
	if expr == nil || info == nil {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		obj := info.ObjectOf(id)
		v, ok := obj.(*types.Var)
		if !ok {
			return true
		}
		for _, p := range errParams {
			if v == p {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// directLoggerErrorReceiver reports whether call resolves to a logger Error /
// ErrorContext / Errorf / Errorln method whose receiver type is one of the
// known logger interface types in loggerInterfaceTypes. Used by the D-14
// emission path to gate the struct_logger_field emission.
func directLoggerErrorReceiver(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return false
	}
	switch sel.Sel.Name {
	case "Error", "ErrorContext", "Errorf", "Errorln":
	default:
		return false
	}
	tv, ok := info.Types[sel.X]
	if !ok {
		return false
	}
	return isLoggerInterfaceType(tv.Type)
}

// directErrErrorIdents returns the *ast.Ident for each direct positional
// `<ident>.Error()` argument of call. Direct means not wrapped inside an
// attribute builder like slog.String("err", err.Error()) - those are handled
// by isAttrBuilderWithErrorMethodCall in error_sinks.go and gated separately.
func directErrErrorIdents(call *ast.CallExpr) []*ast.Ident {
	if call == nil {
		return nil
	}
	var out []*ast.Ident
	for _, a := range call.Args {
		c, ok := a.(*ast.CallExpr)
		if !ok {
			continue
		}
		if !isErrorMethodCall(c) {
			continue
		}
		sel, _ := c.Fun.(*ast.SelectorExpr)
		if sel == nil {
			continue
		}
		if id, ok := sel.X.(*ast.Ident); ok {
			out = append(out, id)
		}
	}
	return out
}

// seedUserInputErrors walks the file for assignments whose right-hand-side
// is a CallExpr containing a USER_INPUT-tainted argument AND whose callee
// lives in a stdlib infrastructure package. The error-typed left-hand-side
// identifiers are recorded in st.taintedErrors. This precise scope (only
// stdlib infrastructure callees, only error-typed LHS) is the D-14 one-hop
// callee-param heuristic that lets `body, err := io.ReadAll(r.Body)` carry
// USER_INPUT taint into err WITHOUT corrupting general taint flow elsewhere.
func (st *fileState) seedUserInputErrors() {
	if st.file == nil {
		return
	}
	if st.taintedErrors == nil {
		st.taintedErrors = map[types.Object]taintMeta{}
	}
	ast.Inspect(st.file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Rhs) != 1 || len(assign.Lhs) < 2 {
			return true
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isInfrastructurePackageCall(call, st.info) {
			return true
		}
		var sourceCtx UserInputContext
		var hasUserInputArg bool
		for _, a := range call.Args {
			if ctx, ok := st.classifyExpr(a); ok {
				sourceCtx = ctx
				hasUserInputArg = true
				break
			}
		}
		if !hasUserInputArg {
			return true
		}
		for _, lhs := range assign.Lhs {
			if !isErrorTypedLhs(lhs, st.info) {
				continue
			}
			id, ok := lhs.(*ast.Ident)
			if !ok {
				continue
			}
			obj := st.info.ObjectOf(id)
			if obj == nil {
				continue
			}
			st.taintedErrors[obj] = taintMeta{source: sourceCtx}
		}
		return true
	})
}

// errIdentInTaintedErrors reports whether id resolves to an object recorded
// in st.taintedErrors. Used by the D-14 emission path.
func (st *fileState) errIdentInTaintedErrors(id *ast.Ident) (UserInputContext, bool) {
	if id == nil || st.taintedErrors == nil {
		return UserInputContext{}, false
	}
	obj := st.info.ObjectOf(id)
	if obj == nil {
		return UserInputContext{}, false
	}
	if meta, ok := st.taintedErrors[obj]; ok {
		return meta.source, true
	}
	return UserInputContext{}, false
}

