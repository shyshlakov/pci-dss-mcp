package httpinputscanner

import (
	"go/ast"
	"go/types"
	"reflect"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// inspectBoundStructPanTags reports whether the enclosing function of
// sinkCall contains a body-decoder call (ShouldBindJSON / Bind /
// json.NewDecoder.Decode etc.) whose &target struct has any field with a
// json or validate tag matching the PAN/CHD keyword class AND sinkCall's
// args contain a DIRECT validator.FieldError.Value() invocation. The
// direct-invocation gate distinguishes the canonical
// `slog.Error("k", fe.Value())` chain (CRITICAL) from indirect chains
// `details[k] = fe.Value(); slog.Any("details", details)` where the map
// hop is too lossy to claim CRITICAL with confidence.
//
// Returns false when the enclosing function cannot be located, the bound
// struct cannot be resolved, no field tag matches PAN/CHD class, or no
// direct fe.Value() invocation appears in sinkCall.Args.
func (st *fileState) inspectBoundStructPanTags(sinkCall *ast.CallExpr) bool {
	if st.file == nil || st.info == nil || sinkCall == nil {
		return false
	}
	if !sinkCallHasDirectValidatorValue(sinkCall, st.info) {
		return false
	}
	enc := enclosingFuncDecl(st.file, sinkCall.Pos())
	if enc == nil || enc.Body == nil {
		return false
	}
	var found bool
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var argExpr ast.Expr
		if src, ok := taint.RecognizeFrameworkInputCall(call, st.info); ok && src.IsBodyDecoder {
			if len(call.Args) > 0 {
				argExpr = call.Args[0]
			}
		} else if jsonDecoderDecodeArg(call, st.info) != nil {
			argExpr = jsonDecoderDecodeArg(call, st.info)
		}
		if argExpr == nil {
			return true
		}
		if structHasPanTagField(argExpr, st.info) {
			found = true
			return false
		}
		return true
	})
	return found
}

// sinkCallHasDirectValidatorValue reports whether any arg of sinkCall (or
// any nested CallExpr inside an arg) directly invokes
// validator.FieldError.Value(). The walk is depth-bounded to the args
// subtree to avoid claiming CRITICAL on through-map chains.
func sinkCallHasDirectValidatorValue(sinkCall *ast.CallExpr, info *types.Info) bool {
	if sinkCall == nil || info == nil {
		return false
	}
	for _, a := range sinkCall.Args {
		if exprIsValidatorFieldErrorValue(a, info) {
			return true
		}
	}
	return false
}

// exprIsValidatorFieldErrorValue checks expr (and nested CallExprs) for a
// resolved *types.Func equal to validator.FieldError.Value.
func exprIsValidatorFieldErrorValue(expr ast.Expr, info *types.Info) bool {
	if expr == nil || info == nil {
		return false
	}
	var found bool
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := taint.ResolveCallee(info, call)
		if fn == nil || fn.Pkg() == nil {
			return true
		}
		if fn.Pkg().Path() != "github.com/go-playground/validator/v10" {
			return true
		}
		if fn.Name() != "Value" {
			return true
		}
		if taint.ReceiverTypeName(fn) != "FieldError" {
			return true
		}
		found = true
		return false
	})
	return found
}

// jsonDecoderDecodeArg returns the &target arg of a `(*json.Decoder).Decode(&r)`
// call, or nil. Recognized as a body-decoder shape outside the gin/echo/fiber
// framework taxonomy.
func jsonDecoderDecodeArg(call *ast.CallExpr, info *types.Info) ast.Expr {
	if call == nil || info == nil {
		return nil
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return nil
	}
	if fn.Pkg().Path() != "encoding/json" {
		return nil
	}
	if fn.Name() != "Decode" {
		return nil
	}
	if taint.ReceiverTypeName(fn) != "Decoder" {
		return nil
	}
	if len(call.Args) > 0 {
		return call.Args[0]
	}
	return nil
}

// structHasPanTagField walks the struct type bound by argExpr (typically
// `&r` where r is a struct value) and returns true when any field has a
// json or validate tag whose first comma-separated value matches the
// PAN/CHD keyword class.
func structHasPanTagField(argExpr ast.Expr, info *types.Info) bool {
	if argExpr == nil || info == nil {
		return false
	}
	target := argExpr
	if u, ok := argExpr.(*ast.UnaryExpr); ok {
		target = u.X
	}
	tv, ok := info.Types[target]
	if !ok {
		return false
	}
	t := tv.Type
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
	stType, ok := named.Underlying().(*types.Struct)
	if !ok {
		return false
	}
	for i := 0; i < stType.NumFields(); i++ {
		f := stType.Field(i)
		if f == nil {
			continue
		}
		tag := stType.Tag(i)
		if tag == "" {
			continue
		}
		if tagFirstValueMatchesPan(tag, "json") {
			return true
		}
		if tagFirstValueMatchesPan(tag, "validate") {
			return true
		}
		// Field name itself can also carry the PAN signal even when the
		// struct has no tags (rare). Fall through to keyword check.
		if matchesPanKeyword(f.Name()) {
			return true
		}
	}
	return false
}

// tagFirstValueMatchesPan extracts the named tag's first comma-separated
// value, lowercased and stripped of separators, then runs PAN-keyword
// matching. The "required" / "len=N" suffix on validate tags is skipped
// because tagFirstValue takes only the first token before the comma.
func tagFirstValueMatchesPan(tag, key string) bool {
	v := reflect.StructTag(tag).Get(key)
	if v == "" {
		return false
	}
	first := v
	for i := 0; i < len(v); i++ {
		if v[i] == ',' {
			first = v[:i]
			break
		}
	}
	return matchesPanKeyword(first)
}
