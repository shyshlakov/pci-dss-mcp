// Package httpinputscanner detects HTTP framework input flowing into log,
// error, and panic sinks without a sanitizer barrier. Implements PCI DSS
// 10.2.1 (audit log content) and 6.2.4 (error response leakage) checks.
//
// Detection rules:
//   - HTTP-INPUT-LOG: framework input reaches a log sink, no sanitizer barrier
//   - HTTP-INPUT-ERROR: framework input baked into fmt.Errorf or written via
//     http.ResponseWriter, no sanitizer barrier
//   - HTTP-INPUT-PANIC: framework input reaches panic(...) or defer recover()
//     re-log path
//   - HTTP-INPUT-TAINT-OFF: emitted as INFO when include_taint=false so callers
//     understand why the rules above did not run
package httpinputscanner

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// HTTPInputScanner emits findings for framework HTTP input reaching log /
// error / panic sinks. It implements scanner.Scanner and the
// reportscanner.taintCapableScanner interface.
type HTTPInputScanner struct{}

// New constructs an HTTPInputScanner. Stateless beyond its method receiver.
func New() *HTTPInputScanner {
	return &HTTPInputScanner{}
}

// Name implements scanner.Scanner.
func (s *HTTPInputScanner) Name() string { return "http_input_taint" }

// Description implements scanner.Scanner.
func (s *HTTPInputScanner) Description() string {
	return "Detect HTTP framework input flowing into log, error, or panic sinks without a sanitizer barrier (PCI DSS 10.2.1, 6.2.4)"
}

// Requirements implements scanner.Scanner. The first two are direct findings;
// 3.3.1 / 3.5.1 fire only on PAN-keyword promotion (HIGH severity path).
func (s *HTTPInputScanner) Requirements() []string {
	return []string{"10.2.1", "6.2.4", "3.3.1", "3.5.1"}
}

// Scan runs the scanner without taint analysis - HTTP-input rules require the
// taint engine, so Scan emits a single HTTP-INPUT-TAINT-OFF INFO finding to
// explain the gap (D-09 backwards-compat).
func (s *HTTPInputScanner) Scan(ctx context.Context, targetPath string) (*scanner.ScanResult, error) {
	return s.ScanFullWithTaint(ctx, targetPath, nil, false, false, false)
}

// ScanFull keeps the fullScanner contract; delegates with taint disabled.
func (s *HTTPInputScanner) ScanFull(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool) (*scanner.ScanResult, error) {
	return s.ScanFullWithTaint(ctx, targetPath, excludePatterns, includeTests, includeUntracked, false)
}

// ScanFullWithTaint performs the full HTTP-input flow analysis. When
// includeTaint=false a single INFO finding is emitted explaining why the
// HTTP-INPUT-* rules did not fire. When the taint engine fails to load (graceful
// degradation), the same INFO finding is emitted with a different reason.
func (s *HTTPInputScanner) ScanFullWithTaint(ctx context.Context, targetPath string, excludePatterns []string, includeTests bool, includeUntracked bool, includeTaint bool) (*scanner.ScanResult, error) {
	start := time.Now()
	result := &scanner.ScanResult{Findings: []scanner.Finding{}}

	if !includeTaint {
		result.Findings = append(result.Findings, taintOffFinding(
			"HTTP-input taint rules require taint analysis enabled. Re-run with include_taint=true for HTTP-INPUT-LOG/-ERROR/-PANIC findings.",
		))
		result.Metadata.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	if absRoot, absErr := filepath.Abs(targetPath); absErr == nil {
		targetPath = absRoot
	}

	engine := taint.GetOrInit(ctx, targetPath)
	if engine == nil {
		result.Findings = append(result.Findings, taintOffFinding(
			"HTTP-input taint rules unavailable: taint engine could not load this project (missing go binary, typecheck errors, or load timeout).",
		))
		result.Metadata.DurationMS = time.Since(start).Milliseconds()
		return result, nil
	}

	pkgs := engine.LoadedPackages()
	for _, pkg := range pkgs {
		if pkg == nil || pkg.TypesInfo == nil || pkg.Fset == nil {
			continue
		}
		// Skip vendor / generated and stdlib + third-party deps - we only emit
		// findings on the target module's own files.
		if !pkgIsInProject(pkg, targetPath) {
			continue
		}
		fileFindings, fileLines := s.scanPackage(pkg)
		result.Findings = append(result.Findings, fileFindings...)
		result.Metadata.ScannedFiles += len(pkg.Syntax)
		result.Metadata.ScannedLines += fileLines
	}

	result.Metadata.DurationMS = time.Since(start).Milliseconds()
	return result, nil
}

// taintOffFinding builds the single INFO finding emitted when taint rules
// cannot run. Description carries the specific reason supplied by the caller.
func taintOffFinding(reason string) scanner.Finding {
	return scanner.Finding{
		RuleID:        "HTTP-INPUT-TAINT-OFF",
		Severity:      scanner.SeverityInfo,
		RequirementID: "10.2.1",
		FilePath:      "(scanner)",
		Line:          0,
		Description:   reason,
		Suggestion:    "Set include_taint=true (default in production scans) to enable framework input flow tracking.",
	}
}

// pkgIsInProject filters out stdlib / third-party packages so HTTP-INPUT
// findings only target the analyzed module's own files. Heuristic: the
// package's GoFiles must reside under the absolutized target path.
func pkgIsInProject(pkg *packages.Package, targetPath string) bool {
	if pkg == nil || len(pkg.GoFiles) == 0 {
		return false
	}
	for _, gf := range pkg.GoFiles {
		if strings.HasPrefix(gf, targetPath) {
			return true
		}
	}
	return false
}

// scanPackage walks every file in a package and emits HTTP-INPUT-* findings.
// It runs the source-seeding pass first, then a cross-procedural pass to
// propagate taint into same-file helper parameters, then sanitizer collection,
// then emission.
func (s *HTTPInputScanner) scanPackage(pkg *packages.Package) ([]scanner.Finding, int) {
	var findings []scanner.Finding
	var totalLines int

	info := pkg.TypesInfo
	for _, f := range pkg.Syntax {
		if f == nil {
			continue
		}
		state := newFileState(pkg, f, info)
		state.collectSources()
		// Two iterations of cross-procedural propagation catch
		// helper-of-helper indirection up to one nesting level (e.g. caller
		// taints A's param, A's body calls B with that param, B's param
		// becomes tainted on the second pass).
		state.propagateCrossProcedural()
		state.propagateCrossProcedural()
		// D-14 one-hop callee-param heuristic: seed err identifiers when
		// their RHS is a stdlib infrastructure call carrying USER_INPUT
		// tainted args (e.g. io.ReadAll(r.Body)).
		state.seedUserInputErrors()
		state.collectSanitizers()
		state.collectPanicSites()
		findings = append(findings, state.emitLogFindings()...)
		findings = append(findings, state.emitErrorFindings()...)
		findings = append(findings, state.emitPanicFindings()...)
		if pkg.Fset != nil {
			totalLines += pkg.Fset.Position(f.End()).Line
		}
	}
	return findings, totalLines
}

// fileState bundles per-file dataflow tracking. The scanner runs an
// intra-procedural USER_INPUT taint pass: identifiers assigned from a
// framework input source are tainted, taint flows through pass-through
// helpers (fmt.Sprintf / Errorf, sanitizer-clearing wrappers, struct-decoder
// fields), and any taint reaching a sink call site emits a finding unless the
// same branch applied a sanitizer.
type fileState struct {
	pkg  *packages.Package
	file *ast.File
	info *types.Info

	// taintedIdents tracks local Vars that hold USER_INPUT-tainted data.
	taintedIdents map[types.Object]taintMeta

	// taintedFields tracks struct fields that became tainted (e.g. via
	// ShouldBindJSON body decoders).
	taintedFields map[*types.Var]taintMeta

	// taintedReturns tracks functions whose return value is currently
	// tainted (intra-file - covers Maskify/Sprintf/Errorf etc.).
	taintedReturns map[*types.Func]taintMeta

	// taintedErrors tracks error-typed identifiers seeded by the D-14
	// one-hop callee-param heuristic - typically err from `io.ReadAll(r.Body)`
	// where the call's args contain USER_INPUT-tainted exprs. This map is
	// SEPARATE from taintedIdents to avoid corrupting general taint flow:
	// only the dedicated D-14 emission path reads it.
	taintedErrors map[types.Object]taintMeta

	// sanitizerBlocks marks ast.BlockStmt nodes whose suffix has applied a
	// sanitizer. Used for branch-aware analysis - the success branch can
	// clear taint while the error branch still emits.
	sanitizerBlocks map[*ast.BlockStmt]bool

	// hasPanicSite is true when this file (or its package) contains a
	// panic(arg) call. Used by D-19 conservative recovery emission.
	hasPanicSite bool
}

// taintMeta carries provenance for a tainted value so severity computation can
// promote to HIGH on PAN-keyword sources.
type taintMeta struct {
	source UserInputContext
}

// UserInputContext captures the textual identifier (path slot name, header
// name, query parameter name) that introduced taint into the current frame.
// SourceIsBodyDecoder marks taint flows that originated at a body-decoder
// source (ShouldBindJSON, BodyParser, c.Request.Body read) so the severity
// classifier can apply the body-source HIGH override even when the field
// identifier itself does not match any keyword class.
//
// BodyBufferChain marks the io.Copy / io.WriteString reverse-flow seeding
// path: the destination object received body content via a stdlib reverse
// propagator AND a forward projector (bytes.Buffer.String / strings.Builder
// .String) returns it. This narrower flag distinguishes the bytes_buffer
// body-write pattern from plain body field reads that pass through stdlib
// helpers like io.ReadAll.
type UserInputContext struct {
	Identifier          string
	Framework           string
	SourceIsBodyDecoder bool
	BodyBufferChain     bool
}

func newFileState(pkg *packages.Package, file *ast.File, info *types.Info) *fileState {
	return &fileState{
		pkg:             pkg,
		file:            file,
		info:            info,
		taintedIdents:   map[types.Object]taintMeta{},
		taintedFields:   map[*types.Var]taintMeta{},
		taintedReturns:  map[*types.Func]taintMeta{},
		taintedErrors:   map[types.Object]taintMeta{},
		sanitizerBlocks: map[*ast.BlockStmt]bool{},
	}
}

// collectSources seeds taint at every USER_INPUT framework input call site
// reachable in this file. It also walks recover() inside defer FuncLits and
// notes panic(arg) sites for D-19.
func (st *fileState) collectSources() {
	ast.Inspect(st.file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			st.applyAssignSeed(node)
		case *ast.CallExpr:
			// Body decoders taint the first by-pointer struct argument's
			// fields.
			if src, ok := taint.RecognizeFrameworkInputCall(node, st.info); ok && src.IsBodyDecoder {
				st.seedBodyDecoderFields(node, src)
			}
			// Plan 21.1-07 reverse-flow seeding: io.Copy / io.CopyN /
			// io.CopyBuffer / io.WriteString with a tainted source arg
			// taints the destination *types.Var. Mirrors the engine catalog
			// at internal/taint/userinput_propagators.go:115-125.
			if dst, src, ok := reverseFlowSourceArg(node, st.info); ok {
				if ctx, tainted := st.classifyExpr(src); tainted {
					ctx.BodyBufferChain = true
					st.seedReverseFlowDest(dst, ctx)
				}
			}
			// Plan 21.1-04 gin recovery callback source: seed the
			// `recovered any` callback parameter with USER_INPUT taint when
			// gin.CustomRecoveryWithWriter / CustomRecovery / RecoveryWithWriter
			// is invoked with an inline FuncLit.
			if vars := taint.RecognizeRecoveryCallback(node, st.info); len(vars) > 0 {
				ctx := UserInputContext{Identifier: "recovered", Framework: "gin"}
				for _, v := range vars {
					st.taintedIdents[v] = taintMeta{source: ctx}
				}
			}
			// panic(arg) site - record for D-19 emission.
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "panic" && len(node.Args) > 0 {
				st.hasPanicSite = true
			}
		}
		return true
	})
}

// seedReverseFlowDest taints the *types.Var referenced by a reverse-flow
// destination expression. Recognizes the &ident shape (UnaryExpr with
// Op=AND) used by io.Copy(&buf, src) and the bare ident shape used when
// the destination is already a pointer or interface value. Other shapes
// (composite literals, function returns) silently no-op per recall-bias.
func (st *fileState) seedReverseFlowDest(dstExpr ast.Expr, ctx UserInputContext) {
	var ident *ast.Ident
	switch x := dstExpr.(type) {
	case *ast.UnaryExpr:
		if x.Op != token.AND {
			return
		}
		if id, ok := x.X.(*ast.Ident); ok {
			ident = id
		}
	case *ast.Ident:
		ident = x
	case *ast.ParenExpr:
		st.seedReverseFlowDest(x.X, ctx)
		return
	}
	if ident == nil {
		return
	}
	obj := st.info.ObjectOf(ident)
	if obj == nil {
		return
	}
	if _, ok := obj.(*types.Var); !ok {
		return
	}
	st.taintedIdents[obj] = taintMeta{source: ctx}
}

// applyAssignSeed handles `x := c.Param("bin")`, `x = r.URL.Path`, and the
// chained `slog.With(taint, ...)` builder pattern, plus passthroughs through
// fmt.Sprintf / Errorf. Multi-return assignments (`id, err := f(taint)`) taint
// every NON-error LHS identifier when the single RHS call has any tainted arg.
// Error results from stdlib infrastructure (io, os, net, etc.) are NOT
// tainted. Error results from same-file helpers ARE tainted because the err
// may wrap the user input.
func (st *fileState) applyAssignSeed(assign *ast.AssignStmt) {
	if len(assign.Lhs) == 0 || len(assign.Rhs) == 0 {
		return
	}
	// Multi-return shape: 1 RHS call, N LHS idents.
	if len(assign.Rhs) == 1 && len(assign.Lhs) > 1 {
		ctx, tainted := st.classifyExpr(assign.Rhs[0])
		if !tainted {
			return
		}
		filterErr := false
		if call, ok := assign.Rhs[0].(*ast.CallExpr); ok {
			filterErr = isInfrastructurePackageCall(call, st.info)
		}
		for _, lhs := range assign.Lhs {
			if filterErr && isErrorTypedLhs(lhs, st.info) {
				continue
			}
			st.applyLhsTaint(lhs, ctx)
		}
		return
	}
	for i, rhs := range assign.Rhs {
		if i >= len(assign.Lhs) {
			break
		}
		ctx, tainted := st.classifyExpr(rhs)
		if !tainted {
			continue
		}
		st.applyLhsTaint(assign.Lhs[i], ctx)
	}
}

// isInfrastructurePackageCall reports whether the callee is in a stdlib /
// infrastructure package whose error returns are NOT user-input-derived
// (io.ReadAll, os.Open, net/http.Get, etc.). When the caller's helper is
// in the same module / project file, taint MAY flow through err.
func isInfrastructurePackageCall(call *ast.CallExpr, info *types.Info) bool {
	if call == nil || info == nil {
		return false
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	pkgPath := fn.Pkg().Path()
	switch pkgPath {
	case "io", "os", "net", "net/http", "encoding/json", "encoding/xml", "encoding/binary",
		"database/sql", "bufio", "bytes", "strconv", "strings", "fmt", "regexp", "errors",
		"context", "log", "log/slog":
		return true
	}
	return false
}

// isErrorTypedLhs reports whether an LHS expression resolves to a value of
// type `error`. Used to suppress error-result tainting in multi-return
// assignments such as `body, err := io.ReadAll(r.Body)` where the err is a
// stdlib error and NOT user input.
func isErrorTypedLhs(lhs ast.Expr, info *types.Info) bool {
	id, ok := lhs.(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.ObjectOf(id)
	if obj == nil {
		return false
	}
	t := obj.Type()
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	if named.Obj() != nil && named.Obj().Pkg() == nil && named.Obj().Name() == "error" {
		return true
	}
	if iface, ok := t.Underlying().(*types.Interface); ok && iface.NumMethods() == 1 {
		m := iface.Method(0)
		if m != nil && m.Name() == "Error" {
			return true
		}
	}
	return false
}

// applyLhsTaint marks an LHS expression as tainted in the file state.
func (st *fileState) applyLhsTaint(lhs ast.Expr, ctx UserInputContext) {
	switch tgt := lhs.(type) {
	case *ast.Ident:
		if obj := st.info.ObjectOf(tgt); obj != nil {
			st.taintedIdents[obj] = taintMeta{source: ctx}
		}
	case *ast.SelectorExpr:
		if obj := st.info.ObjectOf(tgt.Sel); obj != nil {
			st.taintedIdents[obj] = taintMeta{source: ctx}
		}
	case *ast.IndexExpr:
		// Map / slice write: taint the underlying container variable so
		// downstream reads of the container inherit USER_INPUT.
		if id, ok := tgt.X.(*ast.Ident); ok {
			if obj := st.info.ObjectOf(id); obj != nil {
				st.taintedIdents[obj] = taintMeta{source: ctx}
			}
		}
	}
}

// classifyExpr reports whether expr currently carries USER_INPUT taint and
// returns the identifier/framework context that introduced it.
// nolint:gocyclo // exhaustive AST shape dispatch over framework source / propagator / sanitizer cases
func (st *fileState) classifyExpr(expr ast.Expr) (UserInputContext, bool) {
	if expr == nil {
		return UserInputContext{}, false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		// Source recognition first.
		if src, ok := taint.RecognizeFrameworkInputCall(e, st.info); ok && !src.IsBodyDecoder {
			return UserInputContext{
				Identifier: firstStringLiteralArg(e),
				Framework:  src.Framework,
			}, true
		}
		// Sanitizer wrappers clear taint regardless of arg taint.
		if isSanitizerCall(e, st.info) {
			return UserInputContext{}, false
		}
		// Format-validator sanitizers (uuid.Parse, time.Parse, strconv.Atoi,
		// net.ParseIP, mail.ParseAddress, etc.) constrain output to a known
		// format that physically cannot carry PAN/CVV/auth-secret content.
		// The success branch is naturally cleared because the assignment LHS
		// is never seeded; the raw argument keeps its taint so the error
		// branch still fires on `log("invalid", "value", raw)`.
		if isFormatValidatorSanitizer(e, st.info) {
			return UserInputContext{}, false
		}
		// `someErr.Error()` - the .Error() method on error returns a string
		// whose content is the wrapped error's text. If the receiver is
		// USER_INPUT-tainted, the result string carries the same taint.
		if isErrorMethodCall(e) {
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				if ctx, ok := st.classifyExpr(sel.X); ok {
					return ctx, true
				}
			}
		}
		// Verb-aware fmt.Errorf / fmt.Sprintf: when the literal format string
		// has %s/%v/%w at a position whose arg static type implements
		// fmt.Stringer AND that arg is tainted, propagate. Runs BEFORE the
		// uniform passthrough so Stringer-typed args route through this path
		// and surface the receiver's identifier context for severity. Variable
		// format strings fall through to the existing uniform passthrough.
		if ctx, ok := classifyFmtVerbStringer(e, st.info, st); ok {
			return ctx, true
		}
		// Pass-through helper (fmt.Sprintf / Errorf / errors.Wrap / multierror.Append etc.).
		if isPassthroughCall(e, st.info) {
			for _, a := range e.Args {
				if ctx, ok := st.classifyExpr(a); ok {
					return ctx, true
				}
			}
			// Plan 21.1-06 forward method-projector: when the spec is keyed
			// by receiver type (TypeName != "") and no positional arg is
			// tainted, inspect the receiver expression. (*bytes.Buffer).String /
			// .Bytes and (*strings.Builder).String inherit USER_INPUT taint
			// from the receiver, not from the args.
			if isReceiverTypedPassthrough(e, st.info) {
				if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
					if ctx, tainted := st.classifyExpr(sel.X); tainted {
						return ctx, true
					}
				}
			}
		}
		// Inherit taint from a previously tainted callee return.
		if fn := taint.ResolveCallee(st.info, e); fn != nil {
			if meta, ok := st.taintedReturns[fn]; ok {
				return meta.source, true
			}
		}
		// Stop recursion at known log/error/panic sinks - those emit their
		// own findings, and their result type does not propagate USER_INPUT
		// taint to the parent expression. Without this guard `slog.Info` would
		// double-emit through its `slog.String(k, c.Param(...))` arg.
		if _, isLog := isLogSink(e, st.info); isLog {
			return UserInputContext{}, false
		}
		if _, isErr := isErrorSink(e, st.info); isErr {
			return UserInputContext{}, false
		}
		if _, isPan := isPanicSink(e, st.info); isPan {
			return UserInputContext{}, false
		}
		// Recurse into args defensively (covers `string(taint)` and `[]byte(taint)`).
		for _, a := range e.Args {
			if ctx, ok := st.classifyExpr(a); ok {
				return ctx, true
			}
		}
	case *ast.SelectorExpr:
		// Field read of a tainted struct field (body decoder fields).
		if sel, ok := st.info.Selections[e]; ok {
			if v, ok := sel.Obj().(*types.Var); ok {
				if meta, ok := st.taintedFields[v]; ok {
					return meta.source, true
				}
			}
		}
		// URL.Path / URL.RawQuery / URL.RawPath field read.
		if src, ok := taint.RecognizeFrameworkInputFieldRead(e, st.info); ok {
			return UserInputContext{
				Identifier: src.Method,
				Framework:  src.Framework,
			}, true
		}
		// (*http.Request).Body, (*http.Request).URL, (*http.Request).Header
		// field reads. The body is always USER_INPUT; URL.Path / Header.Get
		// chains taint downstream method calls.
		if ctx, ok := classifyHTTPRequestField(e, st.info); ok {
			return ctx, true
		}
		// Identifier resolution for selector targets (e.g. h.log).
		if obj := st.info.ObjectOf(e.Sel); obj != nil {
			if meta, ok := st.taintedIdents[obj]; ok {
				return meta.source, true
			}
		}
		// Recurse into the selector base (e.g. (*req).Field).
		if ctx, ok := st.classifyExpr(e.X); ok {
			return ctx, true
		}
	case *ast.Ident:
		if obj := st.info.ObjectOf(e); obj != nil {
			if meta, ok := st.taintedIdents[obj]; ok {
				return meta.source, true
			}
		}
	case *ast.UnaryExpr:
		return st.classifyExpr(e.X)
	case *ast.ParenExpr:
		return st.classifyExpr(e.X)
	case *ast.StarExpr:
		return st.classifyExpr(e.X)
	case *ast.IndexExpr:
		return st.classifyExpr(e.X)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			if ctx, ok := st.classifyExpr(e.X); ok {
				return ctx, true
			}
			if ctx, ok := st.classifyExpr(e.Y); ok {
				return ctx, true
			}
		}
	case *ast.CompositeLit:
		var safeCtx UserInputContext
		hasSafe := false
		for _, el := range e.Elts {
			target := el
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				target = kv.Value
			}
			if ctx, ok := st.classifyExpr(target); ok {
				if !isSafeIdentifier(ctx.Identifier) {
					return ctx, true
				}
				safeCtx = ctx
				hasSafe = true
			}
		}
		if hasSafe {
			return safeCtx, true
		}
	}
	return UserInputContext{}, false
}

// seedBodyDecoderFields marks every field of the by-pointer struct argument
// passed to ShouldBindJSON-shape body decoders as USER_INPUT-tainted, plus
// the variable itself so `slog.Any("req", req)` is also recognized.
func (st *fileState) seedBodyDecoderFields(call *ast.CallExpr, src taint.UserInputSource) {
	if len(call.Args) == 0 {
		return
	}
	rawArg := call.Args[0]
	arg := rawArg
	if u, ok := arg.(*ast.UnaryExpr); ok {
		arg = u.X
	}
	tv, ok := st.info.Types[arg]
	if !ok {
		return
	}
	t := tv.Type
	if t == nil {
		return
	}
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return
	}
	stType, ok := named.Underlying().(*types.Struct)
	if !ok {
		return
	}
	ctx := UserInputContext{
		Identifier:          named.Obj().Name(),
		Framework:           src.Framework,
		SourceIsBodyDecoder: src.IsBodyDecoder,
	}
	for i := 0; i < stType.NumFields(); i++ {
		f := stType.Field(i)
		if f == nil {
			continue
		}
		st.taintedFields[f] = taintMeta{source: ctx}
		st.taintedIdents[f] = taintMeta{source: ctx}
	}
	// Taint the variable itself so `slog.Any("req", req)` recognizes it.
	if id, ok := arg.(*ast.Ident); ok {
		if obj := st.info.ObjectOf(id); obj != nil {
			st.taintedIdents[obj] = taintMeta{source: ctx}
		}
	}
}

// firstStringLiteralArg returns the first string-literal argument of a call,
// unquoted. Used to extract the path-slot / header / query name from a source
// call site so severity computation can match against PAN keywords.
func firstStringLiteralArg(call *ast.CallExpr) string {
	if call == nil {
		return ""
	}
	for _, a := range call.Args {
		bl, ok := a.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		v := bl.Value
		if len(v) >= 2 && (v[0] == '"' || v[0] == '`') {
			v = v[1 : len(v)-1]
		}
		return v
	}
	return ""
}

// codeSnippet builds a +-2 line context snippet for a finding. Tries to read
// from disk so the rendered snippet matches the source file exactly.
func (st *fileState) codeSnippet(pos token.Position) *scanner.CodeSnippet {
	if pos.Filename == "" {
		return nil
	}
	return scanner.ReadCodeSnippet(pos.Filename, pos.Line)
}

// fmtSeverityFinding builds a finding with shared metadata.
func fmtSeverityFinding(ruleID, requirementID, triageHint, description, suggestion string, severity scanner.Severity, related []string, pos token.Position, snippet *scanner.CodeSnippet) scanner.Finding {
	return scanner.Finding{
		RuleID:              ruleID,
		Severity:            severity,
		RequirementID:       requirementID,
		FilePath:            pos.Filename,
		Line:                pos.Line,
		Column:              pos.Column,
		Description:         description,
		Suggestion:          suggestion,
		RelatedRequirements: related,
		TriageHint:          triageHint,
		CodeSnippet:         snippet,
		Confidence:          "medium",
	}
}

// describeLog renders the LOG finding description so reports can show which
// framework / identifier introduced taint.
func describeLog(ctx UserInputContext, sinkName string) string {
	src := ctx.Identifier
	if src == "" {
		src = "framework input"
	}
	fw := ctx.Framework
	if fw == "" {
		fw = "http"
	}
	return fmt.Sprintf("Raw %s framework input %q reaches log sink %s without sanitizer barrier.", fw, src, sinkName)
}

// describeError renders the ERROR finding description.
func describeError(ctx UserInputContext, sinkName string) string {
	src := ctx.Identifier
	if src == "" {
		src = "framework input"
	}
	fw := ctx.Framework
	if fw == "" {
		fw = "http"
	}
	return fmt.Sprintf("Raw %s framework input %q is baked into %s response/error chain without sanitizer barrier.", fw, src, sinkName)
}

// describePanic renders the PANIC finding description.
func describePanic(ctx UserInputContext, sinkName string) string {
	src := ctx.Identifier
	if src == "" {
		src = "framework input"
	}
	fw := ctx.Framework
	if fw == "" {
		fw = "http"
	}
	return fmt.Sprintf("Raw %s framework input %q reaches %s; recovery middleware will log the value.", fw, src, sinkName)
}

// propagateCrossProcedural walks every call site in the file, looks up the
// callee, and if any tainted arg is passed AND the callee is defined in the
// same file, taints the corresponding parameter. This catches the
// `helper(c, fmt.Errorf("%w", taintedErr))` shape used by central_abort_log
// and error_taint fixtures where the actual log/error sink lives inside the
// helper body.
//
// It also marks helper functions whose tainted parameters flow into a
// returned value as having a tainted return - so callers can inherit taint
// at the call site (`id, err := parseChargeID(c.Param("id"))` -> id and err
// from the wrap path inherit USER_INPUT).
func (st *fileState) propagateCrossProcedural() {
	if st.file == nil || st.info == nil {
		return
	}
	// Build a map of FuncDecls in this file.
	funcByObj := map[*types.Func]*ast.FuncDecl{}
	for _, decl := range st.file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		obj, ok := st.info.Defs[fn.Name].(*types.Func)
		if !ok {
			continue
		}
		funcByObj[obj] = fn
	}

	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn := taint.ResolveCallee(st.info, call)
		if fn == nil {
			return true
		}
		decl, ok := funcByObj[fn]
		if !ok {
			return true
		}
		if decl.Type == nil || decl.Type.Params == nil {
			return true
		}
		// Walk params left-to-right alongside args.
		paramIdx := 0
		var anyTaintedParam bool
		var firstCtx UserInputContext
		for _, paramField := range decl.Type.Params.List {
			for _, paramName := range paramField.Names {
				if paramIdx >= len(call.Args) {
					break
				}
				arg := call.Args[paramIdx]
				paramIdx++
				if ctx, tainted := st.classifyExpr(arg); tainted {
					if !isSafeIdentifier(ctx.Identifier) {
						if obj := st.info.ObjectOf(paramName); obj != nil {
							if _, exists := st.taintedIdents[obj]; !exists {
								st.taintedIdents[obj] = taintMeta{source: ctx}
							}
						}
						if !anyTaintedParam {
							firstCtx = ctx
							anyTaintedParam = true
						}
					}
				}
			}
		}
		// If any param was tainted, mark the function's return as tainted so
		// callers `id, err := f(taint)` can inherit. Conservative: this is
		// the same recall-bias pattern used elsewhere.
		if anyTaintedParam {
			st.taintedReturns[fn] = taintMeta{source: firstCtx}
		}
		return true
	})
}

// classifyHTTPRequestField recognizes USER_INPUT-tainted field reads on
// *http.Request: .Body (always tainted - the request payload), .Form / .PostForm
// (tainted after parsing). The selector receiver type must resolve to
// *net/http.Request.
func classifyHTTPRequestField(sel *ast.SelectorExpr, info *types.Info) (UserInputContext, bool) {
	if sel == nil || sel.Sel == nil || info == nil {
		return UserInputContext{}, false
	}
	tv, ok := info.Types[sel.X]
	if !ok {
		return UserInputContext{}, false
	}
	if !isHTTPRequestType(tv.Type) {
		return UserInputContext{}, false
	}
	switch sel.Sel.Name {
	case "Body":
		return UserInputContext{Identifier: sel.Sel.Name, Framework: "net/http", SourceIsBodyDecoder: true}, true
	case "Form", "PostForm", "MultipartForm":
		return UserInputContext{Identifier: sel.Sel.Name, Framework: "net/http"}, true
	}
	return UserInputContext{}, false
}

// isHTTPRequestType reports whether t is *net/http.Request (with or without
// the pointer wrapper).
func isHTTPRequestType(t types.Type) bool {
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
	return obj.Pkg().Path() == "net/http" && obj.Name() == "Request"
}

// isSlogLoggerType reports whether t is *log/slog.Logger.
func isSlogLoggerType(t types.Type) bool {
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
	return named.Obj() != nil && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "log/slog" && named.Obj().Name() == "Logger"
}

func isLogrusEntryType(t types.Type) bool {
	return isNamedType(t, "github.com/sirupsen/logrus", "Entry")
}

func isLogrusLoggerType(t types.Type) bool {
	return isNamedType(t, "github.com/sirupsen/logrus", "Logger")
}

func isZerologLoggerType(t types.Type) bool {
	return isNamedType(t, "github.com/rs/zerolog", "Logger")
}

func isZapLoggerType(t types.Type) bool {
	return isNamedType(t, "go.uber.org/zap", "Logger") || isNamedType(t, "go.uber.org/zap", "SugaredLogger")
}

func isNamedType(t types.Type, pkgPath, typeName string) bool {
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
	return obj.Pkg().Path() == pkgPath && obj.Name() == typeName
}
