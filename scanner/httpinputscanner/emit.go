package httpinputscanner

import (
	"go/ast"
	"go/token"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// emitLogFindings walks the file and emits HTTP-INPUT-LOG findings for every
// recognized log sink whose value-arg(s) carry USER_INPUT taint. Skips sinks
// inside defer recover() FuncLits so the panic re-log path can claim them.
//
// Inner-call dedup: when both an outer slog.Info AND its inner slog.String
// match as sinks, only the inner call emits. The outer sink would emit at the
// chain root line, which is not the contract's preferred emission point.
func (st *fileState) emitLogFindings() []scanner.Finding {
	if st.pkg == nil || st.pkg.Fset == nil {
		return nil
	}

	type candidate struct {
		call    *ast.CallExpr
		ctx     UserInputContext
		sink    logSinkInfo
		emitPos token.Pos
	}
	var candidates []candidate

	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isInsideDeferRecover(st.file, call) {
			return true
		}
		sink, ok := isLogSink(call, st.info)
		if !ok {
			return true
		}
		ctx, ok := st.anyArgTainted(sink.ArgsToCheck)
		if !ok {
			return true
		}
		if st.callInSanitizedBranch(call) {
			return true
		}
		if _, isErr := isErrorSink(call, st.info); isErr {
			return true
		}
		candidates = append(candidates, candidate{
			call:    call,
			ctx:     ctx,
			sink:    sink,
			emitPos: emissionPos(call),
		})
		return true
	})

	// Drop outer-sink candidates whose inner sink is also a candidate.
	keep := make([]bool, len(candidates))
	for i := range candidates {
		keep[i] = true
	}
	for i, outer := range candidates {
		for j, inner := range candidates {
			if i == j {
				continue
			}
			if astContains(outer.call, inner.call) && outer.call != inner.call {
				keep[i] = false
				break
			}
		}
	}

	var findings []scanner.Finding
	emittedAt := map[token.Pos]bool{}
	for i, c := range candidates {
		if !keep[i] {
			continue
		}
		if emittedAt[c.emitPos] {
			continue
		}
		emittedAt[c.emitPos] = true
		pos := st.pkg.Fset.Position(c.emitPos)
		severity := computeSeverity(c.ctx)
		related := relatedRequirementsForLog(severity)
		desc := describeLog(c.ctx, c.sink.Name)
		f := fmtSeverityFinding(
			"HTTP-INPUT-LOG",
			"10.2.1",
			triageHintLog,
			desc,
			"Apply a sanitizer (mask, redact, sanitize) before logging or replace the value with an own-generated identifier (request_id, internal user_id).",
			severity,
			related,
			pos,
			st.codeSnippet(pos),
		)
		findings = append(findings, f)
	}
	return findings
}

// astContains reports whether outer's subtree contains inner.
func astContains(outer, inner ast.Node) bool {
	if outer == nil || inner == nil {
		return false
	}
	if outer == inner {
		return true
	}
	var found bool
	ast.Inspect(outer, func(n ast.Node) bool {
		if found {
			return false
		}
		if n == inner {
			found = true
			return false
		}
		return true
	})
	return found
}

// emissionPos returns the preferred file position for emitting a finding.
// For SelectorExpr-rooted calls (`x.Method(...)`) we use the position of the
// method name (.Sel) so chains like `log.Info().Str(k, v).Msg(t)` emit at the
// .Str / .Msg line rather than the chain root.
func emissionPos(call *ast.CallExpr) token.Pos {
	if call == nil {
		return token.NoPos
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil {
		return sel.Sel.Pos()
	}
	return call.Pos()
}

// emitErrorFindings walks the file for HTTP-INPUT-ERROR sinks.
func (st *fileState) emitErrorFindings() []scanner.Finding {
	var findings []scanner.Finding
	if st.pkg == nil || st.pkg.Fset == nil {
		return findings
	}
	emittedAt := map[token.Pos]bool{}

	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sink, ok := isErrorSink(call, st.info)
		if !ok {
			return true
		}
		// For zerolog finalizers, also inspect the .Err(err) args from the
		// chain, since the call's own args do not carry the err receiver.
		args := sink.ArgsToCheck
		if zerologArgs := zerologErrArgs(call); len(zerologArgs) > 0 {
			args = append(args, zerologArgs...)
		}
		ctx, ok := st.anyArgTainted(args)
		if !ok {
			return true
		}
		if st.callInSanitizedBranch(call) {
			return true
		}
		emitPos := emissionPos(call)
		if emittedAt[emitPos] {
			return true
		}
		emittedAt[emitPos] = true
		pos := st.pkg.Fset.Position(emitPos)

		desc := describeError(ctx, sink.Name)
		f := fmtSeverityFinding(
			"HTTP-INPUT-ERROR",
			"6.2.4",
			triageHintError,
			desc,
			"Do not bake raw client input into error responses or HTTP write-backs. Return a generic message and log a correlated request_id instead.",
			scanner.SeverityMedium,
			nil,
			pos,
			st.codeSnippet(pos),
		)
		findings = append(findings, f)
		return true
	})
	return findings
}

// emitPanicFindings walks the file for HTTP-INPUT-PANIC sinks.
func (st *fileState) emitPanicFindings() []scanner.Finding {
	var findings []scanner.Finding
	if st.pkg == nil || st.pkg.Fset == nil {
		return findings
	}
	emittedAt := map[token.Pos]bool{}

	emit := func(call *ast.CallExpr, sink panicSinkInfo, ctx UserInputContext) {
		emitPos := emissionPos(call)
		if emittedAt[emitPos] {
			return
		}
		emittedAt[emitPos] = true
		pos := st.pkg.Fset.Position(emitPos)
		desc := describePanic(ctx, sink.Name)
		f := fmtSeverityFinding(
			"HTTP-INPUT-PANIC",
			"10.2.1",
			triageHintPanic,
			desc,
			"Validate or sanitize input before panicking. Recovery middleware logs the panic argument; raw client input ends up in audit trails.",
			scanner.SeverityMedium,
			nil,
			pos,
			st.codeSnippet(pos),
		)
		findings = append(findings, f)
	}

	ast.Inspect(st.file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sink, ok := isPanicSink(call, st.info)
		if !ok {
			return true
		}
		ctx, hasTaint := st.anyArgTainted(sink.ArgsToCheck)
		if !hasTaint {
			return true
		}
		emit(call, sink, ctx)
		return true
	})

	deferSinks := st.collectDeferRecoverSinks()
	if len(deferSinks) > 0 && st.packageHasPanicSite() {
		for _, ds := range deferSinks {
			call, ok := ds.PanicValueExpr.(*ast.CallExpr)
			if !ok {
				continue
			}
			ctx := UserInputContext{Identifier: "recover", Framework: "http"}
			emit(call, ds, ctx)
		}
	}
	return findings
}

// packageHasPanicSite reports whether any file in the same package contains a
// panic(arg) call. Conservative D-19 default is true when the engine cannot
// resolve the package.
func (st *fileState) packageHasPanicSite() bool {
	if st.hasPanicSite {
		return true
	}
	if st.pkg == nil {
		return true
	}
	for _, f := range st.pkg.Syntax {
		if f == nil || f == st.file {
			continue
		}
		var found bool
		ast.Inspect(f, func(n ast.Node) bool {
			if found {
				return false
			}
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := c.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if id.Name == "panic" && len(c.Args) > 0 {
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

// anyArgTainted reports whether any arg in args carries USER_INPUT taint, and
// returns the introducing UserInputContext. Returns the FIRST unsafe-identifier
// source so callers can decide severity. If all tainted args reference safe
// identifiers (X-Request-ID etc.), the call is treated as untainted to avoid
// false positives on audit-middleware patterns.
func (st *fileState) anyArgTainted(args []ast.Expr) (UserInputContext, bool) {
	var safeCtx UserInputContext
	hasSafe := false
	for _, a := range args {
		if ctx, ok := st.classifyExpr(a); ok {
			if !isSafeIdentifier(ctx.Identifier) {
				return ctx, true
			}
			safeCtx = ctx
			hasSafe = true
		}
	}
	if hasSafe {
		// All tainted sources matched safe identifiers - suppress emission.
		_ = safeCtx
		return UserInputContext{}, false
	}
	return UserInputContext{}, false
}

// callInSanitizedBranch reports whether a sanitizer was applied in the same
// AST block as call. Branch-aware analysis - in `if err == nil { mask;
// slog.Info } else { slog.Error(raw) }` the success branch is sanitized and
// the error branch is not.
func (st *fileState) callInSanitizedBranch(call *ast.CallExpr) bool {
	block := enclosingBlock(st.file, call.Pos())
	for block != nil {
		if st.sanitizerBlocks[block] {
			return true
		}
		block = parentBlock(st.file, block)
	}
	return false
}

// parentBlock returns the immediate AST-parent BlockStmt of block, or nil.
func parentBlock(file *ast.File, block *ast.BlockStmt) *ast.BlockStmt {
	if file == nil || block == nil {
		return nil
	}
	var parent *ast.BlockStmt
	stack := []*ast.BlockStmt{}
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return false
		}
		if b, ok := n.(*ast.BlockStmt); ok {
			if b == block {
				if len(stack) > 0 {
					parent = stack[len(stack)-1]
				}
				return false
			}
			stack = append(stack, b)
			return true
		}
		return true
	})
	return parent
}

// isInsideDeferRecover reports whether the given call appears inside a
// `defer func(){ if r := recover(); r != nil { ... } }()` block.
func isInsideDeferRecover(file *ast.File, call *ast.CallExpr) bool {
	if file == nil || call == nil {
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
		if n == call {
			for _, anc := range stack {
				if def, ok := anc.(*ast.DeferStmt); ok {
					if funcLitContainsRecover(def.Call) {
						found = true
						return false
					}
				}
			}
			return false
		}
		stack = append(stack, n)
		return true
	})
	return found
}

// funcLitContainsRecover reports whether a DeferStmt's call expression wraps
// a FuncLit whose body invokes recover().
func funcLitContainsRecover(call *ast.CallExpr) bool {
	if call == nil {
		return false
	}
	lit, ok := call.Fun.(*ast.FuncLit)
	if !ok {
		return false
	}
	var found bool
	ast.Inspect(lit.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := c.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if id.Name == "recover" {
			found = true
			return false
		}
		return true
	})
	return found
}
