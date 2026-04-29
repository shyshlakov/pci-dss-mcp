package httpinputscanner

import (
	"go/ast"
	"go/types"
	"strings"

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

	// (*gin.Context).AbortWithError(code, err) - gin's documented error
	// abort path. ArgsToCheck includes both args; anyArgTainted will find
	// the err arg if it carries USER_INPUT taint via the verb-aware
	// Stringer / fmt.Errorf chain.
	if pkgPath == "github.com/gin-gonic/gin" && recv == "Context" && method == "AbortWithError" {
		return errorSinkInfo{
			Name:        "(*gin.Context).AbortWithError",
			ArgsToCheck: call.Args,
		}, true
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

// errorSinkAuthSecretTypeNames is the broader keyword set used for matching
// Stringer-receiver TYPE names in HTTP-INPUT-ERROR sinks. It retains
// {token, authorization, auth} which Plan 21.1-09 dropped from the
// source-side authSecretKeywords because path-slot literal "token" /
// "Authorization" path-slot would have falsely promoted log sinks. In an
// error chain the Stringer receiver type name (e.g. `Token`) is a stronger
// signal: the developer chose to model an auth-secret value as a typed
// struct AND embedded its String() in an error message. PCI requirement
// 8.6.2 covers leakage of system / application authentication artifacts.
var errorSinkAuthSecretTypeNames = []string{
	"apikey", "api_key", "password", "secret", "bearer",
	"token", "authorization", "auth",
}

// classifyErrorSinkStringerReceiver walks the err-typed args of a recognized
// error sink (typically a fmt.Errorf chain) looking for a Stringer-typed
// sub-argument. When found, the receiver's type name is matched against
// errorSinkAuthSecretTypeNames. Returns severityClassAuthSecret on match.
func classifyErrorSinkStringerReceiver(args []ast.Expr, info *types.Info) severityClass {
	if info == nil {
		return severityClassNone
	}
	for _, arg := range args {
		if c := classifyStringerReceiverIn(arg, info); c != severityClassNone {
			return c
		}
	}
	return severityClassNone
}

// classifyStringerReceiverIn descends into expr looking for Stringer-typed
// arguments and returns severityClassAuthSecret when the receiver type name
// matches errorSinkAuthSecretTypeNames. Walks into fmt.Errorf / fmt.Sprintf
// arg lists.
func classifyStringerReceiverIn(expr ast.Expr, info *types.Info) severityClass {
	if expr == nil {
		return severityClassNone
	}
	if call, ok := expr.(*ast.CallExpr); ok {
		fn := taint.ResolveCallee(info, call)
		if fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "fmt" {
			switch fn.Name() {
			case "Errorf", "Sprintf":
				for _, a := range call.Args[1:] {
					if c := classifyStringerArgType(a, info); c != severityClassNone {
						return c
					}
				}
			}
		}
		return severityClassNone
	}
	return classifyStringerArgType(expr, info)
}

// classifyStringerArgType inspects expr's static type. If it implements
// fmt.Stringer, the named receiver type's name is matched against
// errorSinkAuthSecretTypeNames.
func classifyStringerArgType(expr ast.Expr, info *types.Info) severityClass {
	tv, ok := info.Types[expr]
	if !ok {
		return severityClassNone
	}
	t := tv.Type
	if t == nil {
		return severityClassNone
	}
	if !implementsStringer(t) {
		return severityClassNone
	}
	name := namedTypeName(t)
	if name == "" {
		return severityClassNone
	}
	norm := normalizeIdentifier(name)
	for _, kw := range errorSinkAuthSecretTypeNames {
		if strings.Contains(norm, kw) {
			return severityClassAuthSecret
		}
	}
	return severityClassNone
}

// namedTypeName returns the unqualified named-type name of t, or "" when t
// is not a named type. Pointer receivers are unwrapped.
func namedTypeName(t types.Type) string {
	if t == nil {
		return ""
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	if named.Obj() == nil {
		return ""
	}
	return named.Obj().Name()
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
