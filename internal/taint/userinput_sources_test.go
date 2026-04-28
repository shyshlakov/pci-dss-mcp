package taint

import (
	"context"
	"go/ast"
	"go/types"
	"path/filepath"
	"testing"
)

func httpInputFixtureRoot(t testing.TB) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatalf("abs http_input fixture path: %v", err)
	}
	return abs
}

func loadHTTPInputEngine(t *testing.T) *TaintEngine {
	t.Helper()
	resetAround(t)
	root := httpInputFixtureRoot(t)
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable for vulnerable-payment-service fixture")
	}
	return engine
}

// findCalleeBy walks every loaded file and returns the first CallExpr whose
// callee resolves to a *types.Func matching the predicate, plus its enclosing
// types.Info. Helper for table-driven recognition tests.
func findCalleeBy(t *testing.T, engine *TaintEngine, match func(fn *types.Func, sel *ast.SelectorExpr) bool) (*ast.CallExpr, *types.Info) {
	t.Helper()
	for _, pkg := range engine.pkgs {
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			var found *ast.CallExpr
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, _ := call.Fun.(*ast.SelectorExpr)
				fn := resolveCallee(pkg.TypesInfo, call)
				if fn == nil {
					return true
				}
				if match(fn, sel) {
					found = call
					return false
				}
				return true
			})
			if found != nil {
				return found, pkg.TypesInfo
			}
		}
	}
	return nil, nil
}

func TestFrameworkInputSource(t *testing.T) {
	tt := []struct {
		name   string
		match  func(fn *types.Func, sel *ast.SelectorExpr) bool
		want   string
		isBody bool
	}{
		{
			name: "gin Context.Param",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "Param" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/gin-gonic/gin"
			},
			want: "gin",
		},
		{
			name: "gin Context.GetHeader",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "GetHeader" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/gin-gonic/gin"
			},
			want: "gin",
		},
		{
			name: "gin Context.ShouldBindJSON",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "ShouldBindJSON" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/gin-gonic/gin"
			},
			want:   "gin",
			isBody: true,
		},
		{
			name: "net/http Header.Get",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "Get" && fn.Pkg() != nil && fn.Pkg().Path() == "net/http"
			},
			want: "net/http",
		},
		{
			name: "net/url Values.Get (via r.URL.Query().Get)",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "Get" && fn.Pkg() != nil && fn.Pkg().Path() == "net/url"
			},
			want: "net/http",
		},
		{
			name: "echo Context.Param",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "Param" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/labstack/echo/v4"
			},
			want: "echo",
		},
		{
			name: "fiber Ctx.Query",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "Query" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/gofiber/fiber/v2"
			},
			want: "fiber",
		},
	}

	engine := loadHTTPInputEngine(t)
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			call, info := findCalleeBy(t, engine, tc.match)
			if call == nil {
				t.Skipf("no matching call site found in fixture for %s", tc.name)
			}
			src, ok := isFrameworkInputSource(call, info)
			if !ok {
				t.Fatalf("expected isFrameworkInputSource=true for %s", tc.name)
			}
			if src.Framework != tc.want {
				t.Errorf("framework=%q want=%q", src.Framework, tc.want)
			}
			if src.IsBodyDecoder != tc.isBody {
				t.Errorf("IsBodyDecoder=%v want=%v", src.IsBodyDecoder, tc.isBody)
			}
		})
	}
}

func TestRouteTemplateAccessor(t *testing.T) {
	engine := loadHTTPInputEngine(t)

	tt := []struct {
		name  string
		match func(fn *types.Func, sel *ast.SelectorExpr) bool
	}{
		{
			name: "gin Context.FullPath is a route template (negative)",
			match: func(fn *types.Func, sel *ast.SelectorExpr) bool {
				return fn.Name() == "FullPath" && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/gin-gonic/gin"
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			call, info := findCalleeBy(t, engine, tc.match)
			if call == nil {
				t.Skipf("no matching call site found in fixture for %s", tc.name)
			}
			if !isRouteTemplateAccessor(call, info) {
				t.Fatalf("expected isRouteTemplateAccessor=true for %s", tc.name)
			}
			if _, ok := isFrameworkInputSource(call, info); ok {
				t.Fatalf("expected isFrameworkInputSource=false for negative-list %s", tc.name)
			}
		})
	}
}

func TestFrameworkInputFieldRead(t *testing.T) {
	engine := loadHTTPInputEngine(t)

	// Find a SelectorExpr whose object is *url.URL.Path or RawQuery.
	var found *ast.SelectorExpr
	var foundInfo *types.Info
	for _, pkg := range engine.pkgs {
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name != "Path" && sel.Sel.Name != "RawQuery" {
					return true
				}
				selection, ok := pkg.TypesInfo.Selections[sel]
				if !ok {
					return true
				}
				if v, ok := selection.Obj().(*types.Var); ok && v.Pkg() != nil && v.Pkg().Path() == "net/url" {
					found = sel
					foundInfo = pkg.TypesInfo
					return false
				}
				return true
			})
			if found != nil {
				break
			}
		}
		if found != nil {
			break
		}
	}
	if found == nil {
		t.Skip("no url.URL.Path / RawQuery field read found in fixture")
	}
	src, ok := isFrameworkInputFieldRead(found, foundInfo)
	if !ok {
		t.Fatalf("expected isFrameworkInputFieldRead=true for url.URL field read")
	}
	if src.Framework != "net/http" {
		t.Errorf("framework=%q want=net/http", src.Framework)
	}
}

func TestFrameworkInputSource_NilInfoSafe(t *testing.T) {
	src, ok := isFrameworkInputSource(&ast.CallExpr{}, nil)
	if ok {
		t.Fatalf("expected ok=false on nil info, got src=%+v", src)
	}
	if isRouteTemplateAccessor(&ast.CallExpr{}, nil) {
		t.Fatalf("expected isRouteTemplateAccessor=false on nil info")
	}
	if _, ok := isFrameworkInputFieldRead(&ast.SelectorExpr{Sel: &ast.Ident{Name: "x"}}, nil); ok {
		t.Fatalf("expected isFrameworkInputFieldRead=false on nil info")
	}
}
