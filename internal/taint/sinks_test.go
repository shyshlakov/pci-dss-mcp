package taint

import (
	"context"
	"go/ast"
	"go/types"
	"testing"
)

func TestSinkResolution_PointerIdentity(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "stored_model")
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}

	first := engine.resolveSinks(SinkPattern{Kind: SinkDBStore})
	if len(first) == 0 {
		t.Fatalf("expected non-empty SinkDBStore targets after loading a fixture that imports database/sql")
	}
	second := engine.resolveSinks(SinkPattern{Kind: SinkDBStore})
	if len(first) != len(second) {
		t.Fatalf("expected stable sink count across calls, got %d vs %d", len(first), len(second))
	}
	// Pointer identity: the cached *types.Func must be reference-equal
	// across calls, which is what R5 relies on for comparison.
	for i := range first {
		if first[i].Func != second[i].Func {
			t.Fatalf("resolveSinks returned different *types.Func for entry %d: %p vs %p",
				i, first[i].Func, second[i].Func)
		}
	}

	// Find a db.Exec call site in the fixture AST and verify it resolves to
	// the SAME *types.Func pointer as one of the sink targets.
	var dbExecCall *ast.CallExpr
	var callPkg = engine.pkgs
	_ = callPkg
	for _, pkg := range engine.pkgs {
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "Exec" {
					return true
				}
				if _, ok := pkg.TypesInfo.Selections[sel]; !ok {
					return true
				}
				dbExecCall = call
				return false
			})
			if dbExecCall != nil {
				break
			}
		}
		if dbExecCall != nil {
			break
		}
	}
	if dbExecCall == nil {
		t.Fatalf("no db.Exec call site found in fixture")
	}

	// Resolve the callee via types.Info.Selections and assert it matches a
	// sinkTarget by pointer identity.
	var callee *types.Func
	for _, pkg := range engine.pkgs {
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		sel := dbExecCall.Fun.(*ast.SelectorExpr)
		if s, ok := pkg.TypesInfo.Selections[sel]; ok {
			if f, ok := s.Obj().(*types.Func); ok {
				callee = f
				break
			}
		}
	}
	if callee == nil {
		t.Fatalf("could not resolve db.Exec callee to *types.Func")
	}
	var matched bool
	for _, tgt := range first {
		if tgt.Func == callee {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("db.Exec *types.Func %v not found in resolved SinkDBStore targets", callee.FullName())
	}
}
