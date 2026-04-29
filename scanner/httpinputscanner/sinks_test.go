package httpinputscanner

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestLogSinkLibraryCoverage(t *testing.T) {
	required := []struct {
		pkg    string
		typ    string
		method string
	}{
		{pkg: "log/slog", typ: "Logger", method: "Info"},
		{pkg: "log/slog", typ: "Logger", method: "Error"},
		{pkg: "log/slog", typ: "Logger", method: "ErrorContext"},
		{pkg: "log/slog", method: "Info"},
		{pkg: "log/slog", method: "Error"},
		{pkg: "log/slog", method: "String"},
		{pkg: "log/slog", method: "Any"},
		{pkg: "log/slog", method: "Group"},
		{pkg: "log", method: "Print"},
		{pkg: "log", method: "Printf"},
		{pkg: "github.com/sirupsen/logrus", method: "Info"},
		{pkg: "github.com/sirupsen/logrus", method: "WithFields"},
		{pkg: "github.com/sirupsen/logrus", typ: "Entry", method: "Info"},
		{pkg: "go.uber.org/zap", typ: "Logger", method: "Info"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Msg"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Send"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Str"},
		{pkg: "github.com/go-logr/logr", typ: "Logger", method: "Info"},
		{pkg: "k8s.io/klog/v2", method: "InfoS"},
		{pkg: "github.com/hashicorp/go-hclog", typ: "Logger", method: "Info"},
	}
	for _, want := range required {
		t.Run(want.pkg+"/"+want.typ+"/"+want.method, func(t *testing.T) {
			found := false
			for _, spec := range logSinkLibrary {
				if spec.PkgPath == want.pkg && spec.TypeName == want.typ && spec.Method == want.method {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("logSinkLibrary missing %s.%s.%s", want.pkg, want.typ, want.method)
			}
		})
	}
}

func TestIsErrorSinkAbortWithError(t *testing.T) {
	tt := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "c.AbortWithError with int + fmt.Errorf recognized",
			src: `package main
import (
	"fmt"
	"github.com/gin-gonic/gin"
)
func F(c *gin.Context) { _ = c.AbortWithError(401, fmt.Errorf("nope")) }
`,
			want: true,
		},
		{
			name: "non-gin Context.AbortWithError NOT matched",
			src: `package main
type fakeCtx struct{}
func (fakeCtx) AbortWithError(code int, err error) error { return err }
func F() { var c fakeCtx; _ = c.AbortWithError(401, nil) }
`,
			want: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			conf := types.Config{Importer: importer.Default()}
			info := &types.Info{
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			if _, err := conf.Check("x", fset, []*ast.File{f}, info); err != nil {
				t.Skipf("typecheck (env-dependent): %v", err)
			}
			var found *ast.CallExpr
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "AbortWithError" {
					found = call
					return false
				}
				return true
			})
			if found == nil {
				t.Fatal("did not locate AbortWithError call")
			}
			info2, got := isErrorSink(found, info)
			if got != tc.want {
				t.Fatalf("isErrorSink = %v, want %v (sink: %+v)", got, tc.want, info2)
			}
			if got && info2.Name != "(*gin.Context).AbortWithError" {
				t.Fatalf("sink Name = %q, want (*gin.Context).AbortWithError", info2.Name)
			}
		})
	}
}

func TestClassifyErrorSinkStringerReceiver(t *testing.T) {
	tt := []struct {
		name string
		src  string
		want severityClass
	}{
		{
			name: "fmt.Errorf with Token-typed Stringer arg promotes",
			src: `package main
import "fmt"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() { _ = fmt.Errorf("token: %v", Token{}) }
`,
			want: severityClassAuthSecret,
		},
		{
			name: "fmt.Errorf with non-keyword struct stays none",
			src: `package main
import "fmt"
type Widget struct{ raw string }
func (w Widget) String() string { return w.raw }
func F() { _ = fmt.Errorf("widget: %v", Widget{}) }
`,
			want: severityClassNone,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			conf := types.Config{Importer: importer.Default()}
			info := &types.Info{
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			if _, err := conf.Check("x", fset, []*ast.File{f}, info); err != nil {
				t.Skipf("typecheck (env-dependent): %v", err)
			}
			var found *ast.CallExpr
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel != nil && sel.Sel.Name == "Errorf" {
					found = call
					return false
				}
				return true
			})
			if found == nil {
				t.Fatal("did not locate fmt.Errorf call")
			}
			got := classifyErrorSinkStringerReceiver([]ast.Expr{found}, info)
			if got != tc.want {
				t.Fatalf("classifyErrorSinkStringerReceiver = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestSinkDisplayName(t *testing.T) {
	tt := []struct {
		pkg    string
		recv   string
		method string
		want   string
	}{
		{pkg: "log/slog", recv: "Logger", method: "Info", want: "slog.Info"},
		{pkg: "log", recv: "Logger", method: "Print", want: "log.Print"},
		{pkg: "github.com/sirupsen/logrus", recv: "Entry", method: "Error", want: "logrus.Error"},
		{pkg: "go.uber.org/zap", recv: "Logger", method: "Info", want: "zap.Info"},
		{pkg: "github.com/rs/zerolog", recv: "Event", method: "Send", want: "zerolog.Send"},
		{pkg: "k8s.io/klog/v2", method: "Info", want: "klog.Info"},
	}
	for _, tc := range tt {
		t.Run(tc.want, func(t *testing.T) {
			if got := sinkDisplayName(tc.pkg, tc.recv, tc.method); got != tc.want {
				t.Fatalf("sinkDisplayName(%q,%q,%q) = %q, want %q", tc.pkg, tc.recv, tc.method, got, tc.want)
			}
		})
	}
}
