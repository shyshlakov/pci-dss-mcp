package httpinputscanner

import (
	"go/ast"
	"go/types"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// errorSinkInfo describes a recognized HTTP-INPUT-ERROR sink call.
type errorSinkInfo struct {
	Name        string
	ArgsToCheck []ast.Expr
}

// isErrorSink recognizes the HTTP-INPUT-ERROR sink shapes:
//
//   - http.ResponseWriter.Write([]byte(taint))
//   - fmt.Fprintf(w, fmt, taint) where w is io.Writer-shaped
//   - logger Error / ErrorContext on a tainted err.Error() argument
//   - zerolog Event chain finalizers (.Send / .Msg / .Msgf) on a chain that
//     touched a tainted Err(err)
//
// Note: fmt.Errorf is a passthrough propagator, NOT a sink at the call site.
// The downstream slog.Error("err", err.Error()) call site is what emits the
// HTTP-INPUT-ERROR finding.
func isErrorSink(call *ast.CallExpr, info *types.Info) (errorSinkInfo, bool) {
	if call == nil || info == nil {
		return errorSinkInfo{}, false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		if ok, sinkInfo := matchInterfaceWriterWrite(call, info); ok {
			return sinkInfo, true
		}
		return errorSinkInfo{}, false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recv := taint.ReceiverTypeName(fn)

	// fmt.Errorf is a passthrough at the engine level - emission happens at
	// the downstream log/error site, not on fmt.Errorf itself.
	if pkgPath == "fmt" && method == "Errorf" {
		return errorSinkInfo{}, false
	}

	// fmt.Fprintf(w, fmt, taint) - first arg must be io.Writer-shaped.
	if pkgPath == "fmt" && method == "Fprintf" && len(call.Args) >= 2 {
		if isWriterArg(info, call.Args[0]) {
			return errorSinkInfo{
				Name:        "fmt.Fprintf",
				ArgsToCheck: call.Args[1:],
			}, true
		}
	}

	// (*http.ResponseWriter).Write or any io.Writer.Write whose receiver is
	// HTTP-shaped.
	if method == "Write" && len(call.Args) > 0 {
		if isWriterReceiver(call, info) {
			return errorSinkInfo{
				Name:        "(http.ResponseWriter).Write",
				ArgsToCheck: call.Args,
			}, true
		}
	}

	// Logger Error / ErrorContext methods receiving tainted err.Error().
	if isErrorChainLoggerCall(call, info, fn, recv) {
		return errorSinkInfo{
			Name:        sinkDisplayName(pkgPath, recv, method),
			ArgsToCheck: call.Args,
		}, true
	}

	// slog.String / slog.Any / zap.Error attribute builder whose value-arg is
	// an err.Error() method call - route to HTTP-INPUT-ERROR rule.
	if isAttrBuilderWithErrorMethodCall(call, info) {
		return errorSinkInfo{
			Name:        sinkDisplayName(pkgPath, recv, method),
			ArgsToCheck: call.Args,
		}, true
	}

	// zerolog Event chain finalizers - .Send / .Msg / .Msgf where the chain
	// previously touched .Err(err) with a tainted err.
	if pkgPath == "github.com/rs/zerolog" && recv == "Event" {
		switch method {
		case "Send", "Msg", "Msgf":
			if len(zerologErrArgs(call)) > 0 {
				return errorSinkInfo{
					Name:        "zerolog.Event." + method,
					ArgsToCheck: call.Args,
				}, true
			}
		}
	}

	return errorSinkInfo{}, false
}

// isErrorChainLoggerCall reports whether a logger Error/ErrorContext call
// receives a tainted err.Error() chain.
func isErrorChainLoggerCall(call *ast.CallExpr, info *types.Info, fn *types.Func, recv string) bool {
	if fn == nil {
		return false
	}
	switch fn.Name() {
	case "Error", "ErrorContext", "Errorf", "Errorln":
	default:
		return false
	}
	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	switch pkgPath {
	case "log/slog", "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/rs/zerolog", "github.com/go-logr/logr", "k8s.io/klog/v2", "github.com/hashicorp/go-hclog", "log":
	default:
		if recv == "" {
			return false
		}
	}
	for _, a := range call.Args {
		if isErrorMethodCall(a) {
			return true
		}
	}
	return false
}

// isAttrBuilderWithErrorMethodCall reports whether call is an slog/zap
// attribute builder (slog.String, slog.Any, etc.) whose value-arg is an
// err.Error() method call. Used to route LOG-shaped builder calls into the
// HTTP-INPUT-ERROR rule when the underlying value is an error chain.
func isAttrBuilderWithErrorMethodCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	switch pkgPath {
	case "log/slog":
		switch method {
		case "String", "Any":
		default:
			return false
		}
	case "go.uber.org/zap":
		switch method {
		case "String", "Any", "Error":
		default:
			return false
		}
	default:
		return false
	}
	for _, a := range call.Args {
		if isErrorMethodCall(a) {
			return true
		}
	}
	return false
}

// isErrorMethodCall reports whether expr is a CallExpr to .Error() with no
// arguments. Used to discriminate err.Error() from generic value args.
func isErrorMethodCall(expr ast.Expr) bool {
	c, ok := expr.(*ast.CallExpr)
	if !ok {
		return false
	}
	if len(c.Args) != 0 {
		return false
	}
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel != nil && sel.Sel.Name == "Error"
}

// isWriterArg reports whether expr's static type implements io.Writer or is a
// known HTTP response-writer.
func isWriterArg(info *types.Info, expr ast.Expr) bool {
	if info == nil {
		return false
	}
	tv, ok := info.Types[expr]
	if !ok {
		return false
	}
	t := tv.Type
	return implementsWriter(t)
}

// isWriterReceiver reports whether the receiver of a `.Write(...)` call is a
// known HTTP response-writer.
func isWriterReceiver(call *ast.CallExpr, info *types.Info) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	tv, ok := info.Types[sel.X]
	if !ok {
		return false
	}
	t := tv.Type
	if t == nil {
		return false
	}
	if isHTTPResponseWriter(t) {
		return true
	}
	if isGinResponseWriter(t) {
		return true
	}
	return false
}

// isHTTPResponseWriter reports whether t resolves to net/http.ResponseWriter.
func isHTTPResponseWriter(t types.Type) bool {
	return isNamedType(t, "net/http", "ResponseWriter")
}

// isGinResponseWriter reports whether t is the gin response-writer interface.
func isGinResponseWriter(t types.Type) bool {
	return isNamedType(t, "github.com/gin-gonic/gin", "ResponseWriter")
}

// implementsWriter reports whether t implements io.Writer (i.e. has a
// Write([]byte) (int, error) method).
func implementsWriter(t types.Type) bool {
	if t == nil {
		return false
	}
	mset := types.NewMethodSet(t)
	if mset.Len() == 0 {
		if _, ok := t.(*types.Named); ok {
			mset = types.NewMethodSet(types.NewPointer(t))
		}
	}
	for i := 0; i < mset.Len(); i++ {
		sel := mset.At(i)
		fn, ok := sel.Obj().(*types.Func)
		if !ok {
			continue
		}
		if fn.Name() != "Write" {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok {
			continue
		}
		if sig.Params().Len() != 1 || sig.Results().Len() != 2 {
			continue
		}
		p0 := sig.Params().At(0).Type()
		if !isByteSliceType(p0) {
			continue
		}
		return true
	}
	return false
}

// matchInterfaceWriterWrite handles the unresolved-callee case where
// http.ResponseWriter.Write dispatches through an interface.
func matchInterfaceWriterWrite(call *ast.CallExpr, info *types.Info) (bool, errorSinkInfo) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "Write" {
		return false, errorSinkInfo{}
	}
	if len(call.Args) != 1 {
		return false, errorSinkInfo{}
	}
	tv, ok := info.Types[sel.X]
	if !ok {
		return false, errorSinkInfo{}
	}
	if !isHTTPResponseWriter(tv.Type) && !isGinResponseWriter(tv.Type) {
		return false, errorSinkInfo{}
	}
	return true, errorSinkInfo{
		Name:        "(http.ResponseWriter).Write",
		ArgsToCheck: call.Args,
	}
}

// zerologErrArgs walks the receiver chain of a zerolog Event finalizer call
// and returns the slice of expressions passed to any .Err(...) calls in the
// chain. Used by emitErrorFindings to inspect those args for taint.
func zerologErrArgs(call *ast.CallExpr) []ast.Expr {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	var out []ast.Expr
	cur := sel.X
	for cur != nil {
		c, ok := cur.(*ast.CallExpr)
		if !ok {
			break
		}
		s, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			break
		}
		if s.Sel != nil && s.Sel.Name == "Err" {
			out = append(out, c.Args...)
		}
		cur = s.X
	}
	return out
}
