package taint

import (
	"go/ast"
	"go/types"
)

// frameworkSourceSpec describes one positive-list HTTP input accessor: a
// receiver type plus a method that returns USER_INPUT-tainted data. Free
// functions (chi.URLParam, mux.Vars) use TypeName="" and are matched against
// the package scope.
type frameworkSourceSpec struct {
	PkgPath       string
	TypeName      string
	Method        string
	Framework     string
	IsBodyDecoder bool
}

// userInputSourceLibrary is the baked-in framework recognition list for the
// USER_INPUT taint kind. Entries map to D-02 V1 + V2 + D-16.1 Tier 1 plus the
// fiber + echo Tier-1-required-for-GREEN-gate accessors.
//
// Recognition is by *types.Func / *types.Var pointer identity (matching
// resolveSinks). Two call sites that reach the same method must yield the
// same *types.Func, and that pointer is what we match against here.
var userInputSourceLibrary = []frameworkSourceSpec{
	// gin (github.com/gin-gonic/gin)
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "Param", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "Query", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "DefaultQuery", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "GetHeader", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "GetRawData", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "PostForm", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "DefaultPostForm", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "GetString", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "Get", Framework: "gin"},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "MustGet", Framework: "gin"},
	// gin body decoders - first by-pointer struct argument's fields become tainted.
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindJSON", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindXML", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindYAML", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindTOML", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindMsgPack", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindProtoBuf", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindHeader", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindQuery", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindUri", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "ShouldBindWith", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "BindJSON", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "BindXML", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "BindYAML", Framework: "gin", IsBodyDecoder: true},
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "Bind", Framework: "gin", IsBodyDecoder: true},

	// net/http
	{PkgPath: "net/http", TypeName: "Request", Method: "PathValue", Framework: "net/http"},
	{PkgPath: "net/http", TypeName: "Request", Method: "FormValue", Framework: "net/http"},
	{PkgPath: "net/http", TypeName: "Request", Method: "PostFormValue", Framework: "net/http"},
	{PkgPath: "net/http", TypeName: "Header", Method: "Get", Framework: "net/http"},
	{PkgPath: "net/http", TypeName: "Header", Method: "Values", Framework: "net/http"},

	// net/url (URL.Query() returns url.Values; .Get / .Has / .Values on it)
	{PkgPath: "net/url", TypeName: "Values", Method: "Get", Framework: "net/http"},
	{PkgPath: "net/url", TypeName: "Values", Method: "Has", Framework: "net/http"},
	{PkgPath: "net/url", TypeName: "Values", Method: "Values", Framework: "net/http"},

	// chi (free functions)
	{PkgPath: "github.com/go-chi/chi/v5", TypeName: "", Method: "URLParam", Framework: "chi"},
	{PkgPath: "github.com/go-chi/chi/v5", TypeName: "", Method: "URLParamFromCtx", Framework: "chi"},

	// gorilla/mux (free function returning map[string]string)
	{PkgPath: "github.com/gorilla/mux", TypeName: "", Method: "Vars", Framework: "mux"},

	// echo (interface; recognized via interface method set)
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "Param", Framework: "echo"},
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "QueryParam", Framework: "echo"},
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "FormValue", Framework: "echo"},
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "Bind", Framework: "echo", IsBodyDecoder: true},
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "BindBody", Framework: "echo", IsBodyDecoder: true},

	// fiber (Tier 2 per D-16.2 but required for Phase 21 GREEN per fixture)
	{PkgPath: "github.com/gofiber/fiber/v2", TypeName: "Ctx", Method: "Params", Framework: "fiber"},
	{PkgPath: "github.com/gofiber/fiber/v2", TypeName: "Ctx", Method: "Query", Framework: "fiber"},
	{PkgPath: "github.com/gofiber/fiber/v2", TypeName: "Ctx", Method: "Get", Framework: "fiber"},
	{PkgPath: "github.com/gofiber/fiber/v2", TypeName: "Ctx", Method: "BodyParser", Framework: "fiber", IsBodyDecoder: true},

	// validator (interface) - FieldError.Value() returns the user-supplied value.
	// IsBodyDecoder=true preserves the body-decoder origin signal across the
	// validator boundary: ShouldBindJSON populates the struct, validator returns
	// FieldError.Value() over its fields, and downstream sinks need to know
	// the value originated in a decoded body so PAN-shaped struct fields can
	// promote severity (Plan 21.1-09 RC-6 sub-issue 6b).
	{PkgPath: "github.com/go-playground/validator/v10", TypeName: "FieldError", Method: "Value", Framework: "validator", IsBodyDecoder: true},
}

// routeTemplateNegativeList holds compile-time route-template accessors that
// MUST NOT be flagged as USER_INPUT sources per D-16.5. These return the
// developer-authored route pattern (e.g. "/users/:id"), not the
// user-supplied path slot.
var routeTemplateNegativeList = []frameworkSourceSpec{
	{PkgPath: "github.com/gin-gonic/gin", TypeName: "Context", Method: "FullPath", Framework: "gin"},
	{PkgPath: "github.com/labstack/echo/v4", TypeName: "Context", Method: "Path", Framework: "echo"},
	{PkgPath: "github.com/go-chi/chi/v5", TypeName: "Context", Method: "RoutePattern", Framework: "chi"},
	{PkgPath: "github.com/gorilla/mux", TypeName: "Route", Method: "GetPathTemplate", Framework: "mux"},
}

// isFrameworkInputSource reports whether call resolves to a
// userInputSourceLibrary entry. Returns the resolved UserInputSource and true
// on match; zero value and false otherwise. The route-template negative list
// is checked first and short-circuits.
//
// Recognition is via the call's *types.Func identity - a fake gin-named
// package in the analyzed module would resolve to a different *types.Func
// pointer and therefore not match (T-21.01-05 mitigation).
func isFrameworkInputSource(call *ast.CallExpr, info *types.Info) (UserInputSource, bool) {
	if call == nil || info == nil {
		return UserInputSource{}, false
	}
	if isRouteTemplateAccessor(call, info) {
		return UserInputSource{}, false
	}
	fn := resolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return UserInputSource{}, false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recvName := receiverTypeName(fn)
	for _, spec := range userInputSourceLibrary {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recvName {
			continue
		}
		if spec.TypeName == "" && recvName != "" {
			// caller wants a free function; this is a method.
			continue
		}
		return UserInputSource{
			Package:       spec.PkgPath,
			TypeName:      spec.TypeName,
			Method:        spec.Method,
			Framework:     spec.Framework,
			IsBodyDecoder: spec.IsBodyDecoder,
		}, true
	}
	return UserInputSource{}, false
}

// isRouteTemplateAccessor reports whether call resolves to a known
// compile-time route-template accessor (D-16.5 negative-list). Used to
// short-circuit isFrameworkInputSource so c.FullPath() does NOT taint.
func isRouteTemplateAccessor(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := resolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recvName := receiverTypeName(fn)
	for _, spec := range routeTemplateNegativeList {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recvName {
			continue
		}
		return true
	}
	return false
}

// isFrameworkInputFieldRead recognizes URL.Path / URL.RawQuery / URL.RawPath
// field reads (Pattern P3 / P10) as USER_INPUT sources. This complements
// isFrameworkInputSource for the field-access branch (no method call).
//
// Recognition is via *types.Var identity in info.Selections, matching against
// (net/url.URL).Path and friends.
func isFrameworkInputFieldRead(sel *ast.SelectorExpr, info *types.Info) (UserInputSource, bool) {
	if sel == nil || info == nil || sel.Sel == nil {
		return UserInputSource{}, false
	}
	selection, ok := info.Selections[sel]
	if !ok {
		return UserInputSource{}, false
	}
	v, ok := selection.Obj().(*types.Var)
	if !ok || v.Pkg() == nil {
		return UserInputSource{}, false
	}
	if v.Pkg().Path() != "net/url" {
		return UserInputSource{}, false
	}
	switch v.Name() {
	case "Path", "RawQuery", "RawPath":
		return UserInputSource{
			Package:   "net/url",
			TypeName:  "URL",
			Method:    v.Name(),
			Framework: "net/http",
		}, true
	}
	return UserInputSource{}, false
}

// RecognizeFrameworkInputCall is the exported entry-point for scanners that
// need to identify a CallExpr as a USER_INPUT framework source without going
// through the engine's flow worklist. Returns the resolved UserInputSource on
// match. Mirrors isFrameworkInputSource - same underlying matcher.
func RecognizeFrameworkInputCall(call *ast.CallExpr, info *types.Info) (UserInputSource, bool) {
	return isFrameworkInputSource(call, info)
}

// RecognizeFrameworkInputFieldRead is the exported entry-point for the
// SelectorExpr branch (URL.Path / URL.RawQuery / URL.RawPath).
func RecognizeFrameworkInputFieldRead(sel *ast.SelectorExpr, info *types.Info) (UserInputSource, bool) {
	return isFrameworkInputFieldRead(sel, info)
}

// IsRouteTemplateAccessor is the exported negative-list check (D-16.5). Used
// by scanners to filter out compile-time route-template reads such as
// gin.Context.FullPath / chi.RouteContext.RoutePattern.
func IsRouteTemplateAccessor(call *ast.CallExpr, info *types.Info) bool {
	return isRouteTemplateAccessor(call, info)
}

// ResolveCallee returns the *types.Func for a CallExpr, or nil when the
// callee cannot be resolved (interface dispatch, builtin, etc.). Re-exported
// so scanners performing intra-procedural taint walks can match by pointer
// identity against framework / sanitizer / sink catalogs.
func ResolveCallee(info *types.Info, call *ast.CallExpr) *types.Func {
	return resolveCallee(info, call)
}

// ReceiverTypeName is the exported helper for scanners that need to resolve
// the unqualified receiver type name on a method.
func ReceiverTypeName(fn *types.Func) string {
	return receiverTypeName(fn)
}

// receiverTypeName returns the unqualified receiver type name of a method, or
// "" for a free function. Pointer receivers are unwrapped so *gin.Context and
// gin.Context both yield "Context".
func receiverTypeName(fn *types.Func) string {
	if fn == nil {
		return ""
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return ""
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	if named, ok := t.(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

// ginRecoveryCallbackSpec describes a gin recovery middleware entry point
// whose callback parameter at TaintedParamIndex carries USER_INPUT auxiliary
// taint (D-21.1-04). The callback is the gin.RecoveryFunc value
// `func(c *Context, err any)` and the err slot (index 1) holds handler-
// derived panic values - request body, path, headers, form data.
type ginRecoveryCallbackSpec struct {
	PkgPath           string
	Method            string
	CallbackArgIndex  int
	IsVariadic        bool
	TaintedParamIndex int
	Framework         string
}

var ginRecoveryCallbacks = []ginRecoveryCallbackSpec{
	{
		PkgPath:           "github.com/gin-gonic/gin",
		Method:            "CustomRecoveryWithWriter",
		CallbackArgIndex:  1,
		IsVariadic:        false,
		TaintedParamIndex: 1,
		Framework:         "gin",
	},
	{
		PkgPath:           "github.com/gin-gonic/gin",
		Method:            "CustomRecovery",
		CallbackArgIndex:  0,
		IsVariadic:        false,
		TaintedParamIndex: 1,
		Framework:         "gin",
	},
	{
		PkgPath:           "github.com/gin-gonic/gin",
		Method:            "RecoveryWithWriter",
		CallbackArgIndex:  1,
		IsVariadic:        true,
		TaintedParamIndex: 1,
		Framework:         "gin",
	},
}

// RecognizeRecoveryCallback inspects call. If call resolves to a
// ginRecoveryCallbacks entry, returns the (recovered) *types.Var bindings
// from each *ast.FuncLit callback argument that should be marked
// USER_INPUT-tainted. Returns nil when call does not match.
//
// Pointer-identity match against *types.Func via resolveCallee prevents
// shadow-package spoofing (T-21.01-01 mitigation). Identifier-passed
// callbacks (`gin.CustomRecovery(myRecoveryFn)`) are an acknowledged
// limitation - only FuncLit args at the source site contribute bindings.
func RecognizeRecoveryCallback(call *ast.CallExpr, info *types.Info) []*types.Var {
	if call == nil || info == nil {
		return nil
	}
	fn := resolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return nil
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	for _, spec := range ginRecoveryCallbacks {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.CallbackArgIndex >= len(call.Args) {
			return nil
		}
		var argSlice []ast.Expr
		if spec.IsVariadic {
			argSlice = call.Args[spec.CallbackArgIndex:]
		} else {
			argSlice = []ast.Expr{call.Args[spec.CallbackArgIndex]}
		}
		var tainted []*types.Var
		for _, a := range argSlice {
			fl, ok := a.(*ast.FuncLit)
			if !ok || fl.Type == nil || fl.Type.Params == nil {
				continue
			}
			absIdx := 0
			for _, fld := range fl.Type.Params.List {
				for _, name := range fld.Names {
					if absIdx == spec.TaintedParamIndex {
						if obj, found := info.Defs[name]; found {
							if v, ok := obj.(*types.Var); ok {
								tainted = append(tainted, v)
							}
						}
					}
					absIdx++
				}
			}
		}
		return tainted
	}
	return nil
}
