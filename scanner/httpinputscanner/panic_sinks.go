package httpinputscanner

import (
	"go/ast"
	"go/types"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// panicSinkInfo describes a recognized HTTP-INPUT-PANIC sink call.
type panicSinkInfo struct {
	Name        string
	ArgsToCheck []ast.Expr
	// PanicValueExpr is set when the call is a `slog.Error(...)` inside a
	// defer recover() block - in that case the recover() return value is
	// conservatively treated as USER_INPUT-tainted per D-19.
	PanicValueExpr ast.Expr
}

// isPanicSink recognizes HTTP-INPUT-PANIC sink shapes per D-05 + D-19.
func isPanicSink(call *ast.CallExpr, info *types.Info) (panicSinkInfo, bool) {
	if call == nil || info == nil {
		return panicSinkInfo{}, false
	}

	// Direct panic builtin.
	if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "panic" {
		if len(call.Args) > 0 {
			return panicSinkInfo{
				Name:        "panic",
				ArgsToCheck: call.Args,
			}, true
		}
		return panicSinkInfo{}, false
	}

	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return panicSinkInfo{}, false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recv := taint.ReceiverTypeName(fn)

	switch pkgPath {
	case "log":
		switch method {
		case "Panic", "Panicf", "Panicln":
			return panicSinkInfo{
				Name:        sinkDisplayName(pkgPath, recv, method),
				ArgsToCheck: call.Args,
			}, true
		}
	case "github.com/sirupsen/logrus":
		switch method {
		case "Panic", "Panicf", "Panicln":
			return panicSinkInfo{
				Name:        sinkDisplayName(pkgPath, recv, method),
				ArgsToCheck: call.Args,
			}, true
		}
	case "go.uber.org/zap":
		if recv == "Logger" || recv == "SugaredLogger" {
			switch method {
			case "Panic", "DPanic", "Panicf":
				return panicSinkInfo{
					Name:        sinkDisplayName(pkgPath, recv, method),
					ArgsToCheck: call.Args,
				}, true
			}
		}
	case "github.com/rs/zerolog":
		if recv == "Event" && method == "Panic" {
			return panicSinkInfo{
				Name:        sinkDisplayName(pkgPath, recv, method),
				ArgsToCheck: call.Args,
			}, true
		}
	}

	return panicSinkInfo{}, false
}

// collectPanicSites populates fileState.hasPanicSite. Already populated by
// fileState.collectSources but kept as a no-op stub for the LOG/ERROR/PANIC
// three-step pipeline symmetry.
func (st *fileState) collectPanicSites() {}

// collectDeferRecoverSinks walks the file for `defer func(){ ... recover()
// ... slog.Error(...) ... }()` shapes and returns one panicSinkInfo per
// re-log call site.
func (st *fileState) collectDeferRecoverSinks() []panicSinkInfo {
	var sinks []panicSinkInfo
	if st.file == nil {
		return sinks
	}
	ast.Inspect(st.file, func(n ast.Node) bool {
		def, ok := n.(*ast.DeferStmt)
		if !ok {
			return true
		}
		if !funcLitContainsRecover(def.Call) {
			return true
		}
		lit, ok := def.Call.Fun.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(inner ast.Node) bool {
			c, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isLoggerCallInsideRecover(c, st.info) {
				return true
			}
			sinks = append(sinks, panicSinkInfo{
				Name:           "defer recover() re-log",
				ArgsToCheck:    c.Args,
				PanicValueExpr: c,
			})
			return true
		})
		return true
	})
	_ = types.IsInterface
	return sinks
}

// isLoggerCallInsideRecover reports whether call is a known logger method
// within a defer recover() FuncLit.
func isLoggerCallInsideRecover(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	switch pkgPath {
	case "log/slog", "log", "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/rs/zerolog", "github.com/go-logr/logr", "k8s.io/klog/v2", "github.com/hashicorp/go-hclog":
		return true
	}
	return false
}

// collectGinRecoveryPanicSinks walks the file for
// gin.CustomRecoveryWithWriter / CustomRecovery / RecoveryWithWriter
// invocations with a FuncLit callback, then walks each FuncLit body for
// logger calls whose args reach the `recovered any` *types.Var. Each match
// is returned as a panicSinkInfo with the inner logger call's position.
//
// Plan 21.1-04 D-04 contract: recovery middleware logs the panic value;
// the leak surface is the logger call inside the callback, not the
// CustomRecovery installer call.
func (st *fileState) collectGinRecoveryPanicSinks() []ginRecoveryPanicSink {
	var sinks []ginRecoveryPanicSink
	if st.file == nil {
		return sinks
	}
	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		recoveredVars := taint.RecognizeRecoveryCallback(call, st.info)
		if len(recoveredVars) == 0 {
			return true
		}
		varSet := make(map[*types.Var]bool, len(recoveredVars))
		for _, v := range recoveredVars {
			varSet[v] = true
		}
		for _, arg := range call.Args {
			fl, ok := arg.(*ast.FuncLit)
			if !ok {
				continue
			}
			ast.Inspect(fl.Body, func(inner ast.Node) bool {
				innerCall, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if _, isLog := isLogSink(innerCall, st.info); !isLog {
					return true
				}
				if !exprReachesVar(innerCall, varSet, st.info) {
					return true
				}
				sinks = append(sinks, ginRecoveryPanicSink{
					installerCall: call,
					innerCall:     innerCall,
					funcLit:       fl,
				})
				return true
			})
		}
		return true
	})
	return sinks
}

// ginRecoveryPanicSink describes a logger call inside a gin recovery
// callback FuncLit body whose args reach the `recovered` *types.Var.
type ginRecoveryPanicSink struct {
	installerCall *ast.CallExpr
	innerCall     *ast.CallExpr
	funcLit       *ast.FuncLit
}

// exprReachesVar walks call args looking for an Ident or sub-expression
// whose resolved object is in vars. Used to confirm a logger call inside
// a recovery callback consumes the `recovered` parameter.
func exprReachesVar(call *ast.CallExpr, vars map[*types.Var]bool, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	var found bool
	for _, a := range call.Args {
		ast.Inspect(a, func(n ast.Node) bool {
			if found {
				return false
			}
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			obj := info.ObjectOf(id)
			if v, ok := obj.(*types.Var); ok && vars[v] {
				found = true
				return false
			}
			return true
		})
		if found {
			return true
		}
	}
	return false
}

// isInsideRecoveryCallback reports whether node is inside a *ast.FuncLit
// whose enclosing CallExpr resolves to a gin recovery installer
// (CustomRecoveryWithWriter / CustomRecovery / RecoveryWithWriter). Used
// by emitLogFindings to skip log sinks inside recovery callback FuncLits
// so emitPanicFindings can claim them via the dedicated PANIC shape.
func isInsideRecoveryCallback(file *ast.File, target ast.Node, info *types.Info) bool {
	if file == nil || target == nil || info == nil {
		return false
	}
	var found bool
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if n == target {
			for i := len(stack) - 1; i >= 0; i-- {
				fl, ok := stack[i].(*ast.FuncLit)
				if !ok {
					continue
				}
				for j := i - 1; j >= 0; j-- {
					call, ok := stack[j].(*ast.CallExpr)
					if !ok {
						continue
					}
					if installerCallContainsFuncLit(call, fl, info) {
						found = true
						return false
					}
					break
				}
			}
			return false
		}
		stack = append(stack, n)
		return true
	})
	return found
}

// installerCallContainsFuncLit returns true if call resolves to a gin
// recovery installer AND fl is one of its callback FuncLit args.
func installerCallContainsFuncLit(call *ast.CallExpr, fl *ast.FuncLit, info *types.Info) bool {
	vars := taint.RecognizeRecoveryCallback(call, info)
	if len(vars) == 0 {
		return false
	}
	for _, a := range call.Args {
		if a == fl {
			return true
		}
	}
	return false
}
