package httpinputscanner

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// fmtVerbRegex matches a Go fmt verb allowing flags, width, and precision per
// the canonical grammar `%[flags][width][.precision][verb]`. The single capture
// group records the verb letter so callers can decide whether the verb invokes
// fmt.Stringer. Callers must pre-strip `%%` escapes before applying the regex
// so escape sequences do not consume verb-position counters.
var fmtVerbRegex = regexp.MustCompile(`%[+\-# 0]*\d*(?:\.\d+)?([vsdwxXoUcfgeEbqtTpFGOZ])`)

// implementsStringer reports whether t (or its pointer) has a method
// `String() string`. The pattern mirrors implementsWriter in error_sinks.go so
// the verb-aware path resolves Stringer satisfaction the same way the engine
// resolves io.Writer satisfaction for HTTP-INPUT-ERROR sinks.
func implementsStringer(t types.Type) bool {
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
		if !ok || fn.Name() != "String" {
			continue
		}
		sig, ok := fn.Type().(*types.Signature)
		if !ok || sig.Params().Len() != 0 || sig.Results().Len() != 1 {
			continue
		}
		if isStringType(sig.Results().At(0).Type()) {
			return true
		}
	}
	return false
}

// verbInvokesStringer reports whether the format verb at variadic position
// argIdx invokes fmt.Stringer. Only `%s`, `%v`, and `%w` invoke Stringer per
// the fmt package contract. Numeric verbs (%d/%x/%o/%b/%t/%c/%U) and the
// quoting verb %q produce numeric or quoted output that does not call
// String() and therefore cannot propagate Stringer-receiver state.
//
// argIdx is zero-based among VARIADIC arguments (NOT call.Args overall) -
// callers offset from call.Args[1:] because call.Args[0] is the format string.
//
// `%%` escape sequences are stripped before regex application so they do not
// consume a verb-position counter.
func verbInvokesStringer(formatStr string, argIdx int) bool {
	stripped := strings.ReplaceAll(formatStr, "%%", "")
	matches := fmtVerbRegex.FindAllStringSubmatch(stripped, -1)
	if argIdx < 0 || argIdx >= len(matches) {
		return false
	}
	switch matches[argIdx][1] {
	case "v", "s", "w":
		return true
	}
	return false
}

// isFmtErrorfVerbStringer reports whether call is fmt.Errorf or fmt.Sprintf
// with a literal format string AND has at least one Stringer-typed arg at a
// verb-aware position whose receiver carries USER_INPUT taint via existing
// struct-field propagation.
//
// On match, callers should treat the call's return value as USER_INPUT-tainted
// regardless of whether the existing uniform passthrough already handled it -
// the verb-aware path catches Stringer-typed arguments whose own taint state
// is not directly visible at the call args (a struct that holds a tainted
// field but is itself stored in a non-tainted local). For the
// stringer_token_errorf.go fixture, the local `t Token` is already in
// taintedIdents thanks to composite-literal propagation, so the existing
// passthrough also catches it; verb-aware closes the recall hole when the
// composite-literal hop does not seed the variable directly.
//
// Variable format strings (call.Args[0] not *ast.BasicLit) fall back to the
// existing uniform passthrough - SSA territory, deferred to Phase 26.
func isFmtErrorfVerbStringer(call *ast.CallExpr, info *types.Info, st *fileState) bool {
	_, ok := classifyFmtVerbStringer(call, info, st)
	return ok
}

// classifyFmtVerbStringer is the workhorse used by isFmtErrorfVerbStringer and
// classifyExpr's CallExpr branch. It performs the verb-aware dispatch and
// returns the introducing UserInputContext on the first matching arg so the
// caller does not have to walk arguments twice.
func classifyFmtVerbStringer(call *ast.CallExpr, info *types.Info, st *fileState) (UserInputContext, bool) {
	if call == nil || info == nil || st == nil || len(call.Args) < 2 {
		return UserInputContext{}, false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return UserInputContext{}, false
	}
	if fn.Pkg().Path() != "fmt" {
		return UserInputContext{}, false
	}
	switch fn.Name() {
	case "Errorf", "Sprintf":
	default:
		return UserInputContext{}, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return UserInputContext{}, false
	}
	formatStr, err := strconv.Unquote(lit.Value)
	if err != nil {
		return UserInputContext{}, false
	}
	for argIdx, a := range call.Args[1:] {
		if !verbInvokesStringer(formatStr, argIdx) {
			continue
		}
		if !implementsStringer(info.TypeOf(a)) {
			continue
		}
		if ctx, tainted := st.classifyExpr(a); tainted {
			return ctx, true
		}
	}
	return UserInputContext{}, false
}
