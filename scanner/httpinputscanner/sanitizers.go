package httpinputscanner

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
)

// D-04 sanitizer recognition + D-15 deferral note: Track A only recognizes
// public mask/redact/sanitize shapes plus heuristic regex-redact patterns.
// Project-specific masker recognition is user-configurable via Phase 25 YAML
// rules and is explicitly NOT shipped here.

// passthroughLibrary mirrors the engine's userInputPassthrough catalog; tools
// recognized here propagate USER_INPUT taint from any tainted arg to the
// return value. Used by scanner.classifyExpr to inherit taint through wrappers
// like fmt.Sprintf / fmt.Errorf / errors.Wrap / multierror.Append.
type passthroughSpec struct {
	PkgPath  string
	TypeName string
	Method   string
}

var passthroughLibrary = []passthroughSpec{
	{PkgPath: "fmt", Method: "Sprintf"},
	{PkgPath: "fmt", Method: "Sprint"},
	{PkgPath: "fmt", Method: "Sprintln"},
	{PkgPath: "fmt", Method: "Errorf"},

	{PkgPath: "errors", Method: "Join"},
	{PkgPath: "errors", Method: "New"},

	{PkgPath: "github.com/pkg/errors", Method: "Wrap"},
	{PkgPath: "github.com/pkg/errors", Method: "Wrapf"},
	{PkgPath: "github.com/pkg/errors", Method: "WithMessage"},
	{PkgPath: "github.com/pkg/errors", Method: "WithMessagef"},

	{PkgPath: "github.com/cockroachdb/errors", Method: "Wrap"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "Wrapf"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "WithMessage"},
	{PkgPath: "github.com/cockroachdb/errors", Method: "WithSafeDetails"},

	{PkgPath: "github.com/hashicorp/go-multierror", Method: "Append"},

	{PkgPath: "go.uber.org/multierr", Method: "Append"},
	{PkgPath: "go.uber.org/multierr", Method: "Combine"},

	{PkgPath: "github.com/rotisserie/eris", Method: "Wrap"},
	{PkgPath: "github.com/rotisserie/eris", Method: "Wrapf"},

	{PkgPath: "strings", Method: "Join"},
	{PkgPath: "context", Method: "WithValue"},
}

// isPassthroughCall reports whether call is a recognized USER_INPUT
// pass-through wrapper. Recognition is by *types.Func pointer identity.
func isPassthroughCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recv := taint.ReceiverTypeName(fn)
	for _, spec := range passthroughLibrary {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recv {
			continue
		}
		return true
	}
	if recv == "Error" && pkgPath == "github.com/hashicorp/go-multierror" && method == "Error" {
		return true
	}
	return false
}

// formatValidatorTable lists stdlib + popular library parsers that constrain
// their output to a known format that physically cannot carry PAN/CVV/auth-secret
// content. When a USER_INPUT-tainted value passes through, the returned value
// is no longer tainted on the success path.
//
// Branch-aware semantics fall out naturally because the dispatcher is consulted
// inside classifyExpr: assignments of the form `id, err := uuid.Parse(s)` see
// the RHS classified as untainted and therefore never seed `id`. The raw
// argument `s` keeps its taint, so `if err != nil { log("invalid", "value", s) }`
// still fires.
//
// url.Parse and ParseRequestURI are deliberately omitted: the engine has no
// per-field taint state, so a whole-value sanitizer would falsely clear
// URL.RawQuery / URL.Fragment which carry raw substrings. Existing
// isFrameworkInputFieldRead / classifyHTTPRequestField already recognize those
// fields as separate sources, so per-field semantics already work for the URL
// case.
//
// Recognition is by *types.Func pointer identity resolved against the loaded
// module - a malicious package named "uuid" with a Parse free function cannot
// spoof the google/uuid recognition because it resolves to a different
// *types.Func.
var formatValidatorTable = []passthroughSpec{
	{PkgPath: "github.com/google/uuid", Method: "Parse"},
	{PkgPath: "github.com/google/uuid", Method: "MustParse"},
	{PkgPath: "github.com/google/uuid", Method: "ParseBytes"},

	{PkgPath: "github.com/gofrs/uuid", Method: "FromString"},
	{PkgPath: "github.com/gofrs/uuid", Method: "FromBytes"},
	{PkgPath: "github.com/gofrs/uuid", TypeName: "UUID", Method: "Parse"},

	{PkgPath: "time", Method: "Parse"},
	{PkgPath: "time", Method: "ParseInLocation"},
	{PkgPath: "time", Method: "ParseDuration"},

	{PkgPath: "strconv", Method: "Atoi"},
	{PkgPath: "strconv", Method: "ParseInt"},
	{PkgPath: "strconv", Method: "ParseUint"},
	{PkgPath: "strconv", Method: "ParseFloat"},
	{PkgPath: "strconv", Method: "ParseBool"},

	{PkgPath: "net", Method: "ParseIP"},
	{PkgPath: "net", Method: "ParseCIDR"},

	{PkgPath: "net/netip", Method: "ParseAddr"},
	{PkgPath: "net/netip", Method: "ParseAddrPort"},
	{PkgPath: "net/netip", Method: "ParsePrefix"},

	{PkgPath: "net/mail", Method: "ParseAddress"},
	{PkgPath: "net/mail", Method: "ParseAddressList"},
}

// isFormatValidatorSanitizer reports whether call resolves to a
// formatValidatorTable entry. On match, the call's return value is treated as
// a sanitized format-bound value and classifyExpr returns false.
func isFormatValidatorSanitizer(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	return matchFormatValidator(fn)
}

// matchFormatValidator dispatches a resolved *types.Func against
// formatValidatorTable using PkgPath + receiver-type-name + method-name as the
// match tuple. Free-function entries (TypeName == "") do not match resolved
// methods and method entries (TypeName != "") only match the matching
// receiver. Public for testing - end-to-end tests prefer isFormatValidatorSanitizer.
func matchFormatValidator(fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recv := taint.ReceiverTypeName(fn)
	for _, spec := range formatValidatorTable {
		if spec.PkgPath != pkgPath || spec.Method != method {
			continue
		}
		if spec.TypeName != "" && spec.TypeName != recv {
			continue
		}
		if spec.TypeName == "" && recv != "" {
			continue
		}
		return true
	}
	return false
}

// sanitizerNameRegex matches identifier names that suggest masking / redaction
// behavior. Used by isFunctionShapeMasker for the function-shape recognizer
// per D-04 V2.
var sanitizerNameRegex = regexp.MustCompile(`(?i)(?:^|[_-])(mask|maskify|redact|sanitize|scrub|obfuscate|hide|strip)`)

// digitRunRegex catches regex literals targeting card-number digit runs that
// signal a redact-shaped sanitizer.
var digitRunRegex = regexp.MustCompile(`\\d\{|\[0-9\]\{`)

// isSanitizerCall reports whether call resolves to a recognized sanitizer
// barrier (D-04 V1 + V2 shapes).
//
// Project-specific masker shapes are deferred to Phase 25 user-configurable
// YAML rules per D-15 and CONTEXT.md `<deferred>` block - they are NOT
// shipped here.
func isSanitizerCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil {
		return false
	}
	if fn.Pkg() != nil {
		pkgPath := fn.Pkg().Path()
		if isPublicMaskPackagePath(pkgPath) {
			return true
		}
	}
	if isFunctionShapeMasker(fn) {
		return true
	}
	if isMethodOnStructMasker(fn) {
		return true
	}
	if isRegexRedact(call, info, fn) {
		return true
	}
	return false
}

// isPublicMaskPackagePath returns true when the package path matches a
// well-known public masker package family.
func isPublicMaskPackagePath(pkgPath string) bool {
	if pkgPath == "" {
		return false
	}
	lc := strings.ToLower(pkgPath)
	for _, suffix := range []string{"/mask", "/redact", "/sanitize", "/scrub"} {
		if strings.HasSuffix(lc, suffix) || strings.Contains(lc, suffix+"/") {
			return true
		}
	}
	if strings.HasSuffix(lc, "/card") || strings.Contains(lc, "/card/") {
		return true
	}
	return false
}

// isFunctionShapeMasker recognizes the V2 function-shape masker. The signature
// must be func(string) string or func([]byte) []byte AND the function name
// must contain a mask/redact/sanitize substring.
func isFunctionShapeMasker(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	if !sanitizerNameRegex.MatchString(fn.Name()) {
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}
	if sig.Params().Len() != 1 || sig.Results().Len() != 1 {
		return false
	}
	in := sig.Params().At(0).Type()
	out := sig.Results().At(0).Type()
	if isStringType(in) && isStringType(out) {
		return true
	}
	if isByteSliceType(in) && isByteSliceType(out) {
		return true
	}
	return false
}

// isMethodOnStructMasker recognizes the V2 method-on-struct masker.
func isMethodOnStructMasker(fn *types.Func) bool {
	if fn == nil {
		return false
	}
	switch fn.Name() {
	case "Mask", "Maskify", "Redact", "Sanitize", "Scrub":
	default:
		return false
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	t := sig.Recv().Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	if _, ok := named.Underlying().(*types.Struct); !ok {
		return false
	}
	if sig.Params().Len() == 1 && sig.Results().Len() == 1 {
		in := sig.Params().At(0).Type()
		out := sig.Results().At(0).Type()
		if (isStringType(in) && isStringType(out)) || (isByteSliceType(in) && isByteSliceType(out)) {
			return true
		}
	}
	return false
}

// isRegexRedact recognizes (*regexp.Regexp).ReplaceAll calls whose pattern
// source suggests card-number digit-run redaction.
func isRegexRedact(call *ast.CallExpr, info *types.Info, fn *types.Func) bool {
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	if fn.Pkg().Path() != "regexp" {
		return false
	}
	switch fn.Name() {
	case "ReplaceAll", "ReplaceAllString", "ReplaceAllStringFunc", "ReplaceAllLiteral", "ReplaceAllLiteralString":
	default:
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recvCall, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return false
	}
	recvFn := taint.ResolveCallee(info, recvCall)
	if recvFn == nil || recvFn.Pkg() == nil || recvFn.Pkg().Path() != "regexp" {
		return false
	}
	if recvFn.Name() != "MustCompile" && recvFn.Name() != "Compile" {
		return false
	}
	if len(recvCall.Args) == 0 {
		return false
	}
	bl, ok := recvCall.Args[0].(*ast.BasicLit)
	if !ok {
		return false
	}
	if digitRunRegex.MatchString(bl.Value) {
		return true
	}
	return false
}

// collectSanitizers walks the file for sanitizer barrier calls and records
// the enclosing block per branch-aware analysis (D-04 V2 invariant).
func (st *fileState) collectSanitizers() {
	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if !isSanitizerCall(call, st.info) {
			return true
		}
		if block := enclosingBlock(st.file, call.Pos()); block != nil {
			st.sanitizerBlocks[block] = true
		}
		return true
	})
}

// enclosingBlock returns the innermost ast.BlockStmt that contains pos. Used
// for branch-aware analysis - a sanitizer in `if err == nil { ... }` clears
// taint only inside that block.
func enclosingBlock(file *ast.File, pos token.Pos) *ast.BlockStmt {
	var found *ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if block.Pos() <= pos && pos <= block.End() {
			found = block
		}
		return true
	})
	return found
}

// isStringType reports whether t resolves to a basic string.
func isStringType(t types.Type) bool {
	if t == nil {
		return false
	}
	if b, ok := t.Underlying().(*types.Basic); ok {
		return b.Kind() == types.String
	}
	return false
}

// isByteSliceType reports whether t resolves to []byte.
func isByteSliceType(t types.Type) bool {
	if t == nil {
		return false
	}
	slice, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := slice.Elem().Underlying().(*types.Basic)
	if !ok {
		return false
	}
	return b.Kind() == types.Byte || b.Kind() == types.Uint8
}
