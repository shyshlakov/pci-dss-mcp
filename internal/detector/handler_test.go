package detector

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseSource is a helper that parses a Go source string and returns the file AST.
func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("failed to parse source: %v", err)
	}
	return file
}

func TestDetectFramework(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want Framework
	}{
		{
			name: "net/http import",
			src:  `package main; import "net/http"`,
			want: FrameworkNetHTTP,
		},
		{
			name: "gin import",
			src:  `package main; import "github.com/gin-gonic/gin"`,
			want: FrameworkGin,
		},
		{
			name: "echo import",
			src:  `package main; import "github.com/labstack/echo"`,
			want: FrameworkEcho,
		},
		{
			name: "echo v4 import",
			src:  `package main; import "github.com/labstack/echo/v4"`,
			want: FrameworkEcho,
		},
		{
			name: "chi import",
			src:  `package main; import "github.com/go-chi/chi"`,
			want: FrameworkNetHTTP,
		},
		{
			name: "chi v5 import",
			src:  `package main; import "github.com/go-chi/chi/v5"`,
			want: FrameworkNetHTTP,
		},
		{
			name: "no HTTP import",
			src:  `package main; import "fmt"`,
			want: FrameworkUnknown,
		},
		{
			name: "gin wins over net/http",
			src:  `package main; import ("net/http"; "github.com/gin-gonic/gin")`,
			want: FrameworkGin,
		},
		{
			name: "echo wins over net/http",
			src:  `package main; import ("net/http"; "github.com/labstack/echo")`,
			want: FrameworkEcho,
		},
		{
			name: "no imports at all",
			src:  `package main`,
			want: FrameworkUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := parseSource(t, tt.src)
			got := DetectFramework(file)
			if got != tt.want {
				t.Errorf("DetectFramework() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestIsHTTPHandler(t *testing.T) {
	tests := []struct {
		name string
		src  string
		fw   Framework
		want bool
	}{
		{
			name: "net/http handler",
			src: `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {}`,
			fw:   FrameworkNetHTTP,
			want: true,
		},
		{
			name: "gin handler",
			src: `package main
import "github.com/gin-gonic/gin"
func handler(c *gin.Context) {}`,
			fw:   FrameworkGin,
			want: true,
		},
		{
			name: "echo handler",
			src: `package main
import "github.com/labstack/echo"
func handler(c echo.Context) {}`,
			fw:   FrameworkEcho,
			want: true,
		},
		{
			name: "not a handler",
			src:  `package main; func doStuff(x int) {}`,
			fw:   FrameworkNetHTTP,
			want: false,
		},
		{
			name: "unknown framework defaults to net/http check",
			src: `package main
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {}`,
			fw:   FrameworkUnknown,
			want: true,
		},
		{
			name: "nil params",
			src:  `package main; func handler() {}`,
			fw:   FrameworkNetHTTP,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := parseSource(t, tt.src)
			// Find the first FuncDecl.
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					fn = fd
					break
				}
			}
			if fn == nil {
				t.Fatal("no FuncDecl found in source")
			}
			got := IsHTTPHandler(fn, tt.fw)
			if got != tt.want {
				t.Errorf("IsHTTPHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTypeExprString(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "SelectorExpr (pkg.Type)",
			src:  `package main; import "net/http"; func f(w http.ResponseWriter) {}`,
			want: "http.ResponseWriter",
		},
		{
			name: "Ident (plain type)",
			src:  `package main; func f(x int) {}`,
			want: "int",
		},
		{
			name: "StarExpr (pointer type)",
			src:  `package main; import "net/http"; func f(r *http.Request) {}`,
			want: "*http.Request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := parseSource(t, tt.src)
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok {
					fn = fd
					break
				}
			}
			if fn == nil {
				t.Fatal("no FuncDecl found")
			}
			if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
				t.Fatal("no params found")
			}
			got := TypeExprString(fn.Type.Params.List[0].Type)
			if got != tt.want {
				t.Errorf("TypeExprString() = %q, want %q", got, tt.want)
			}
		})
	}

	// Test nil input.
	t.Run("nil input", func(t *testing.T) {
		got := TypeExprString(nil)
		if got != "" {
			t.Errorf("TypeExprString(nil) = %q, want empty string", got)
		}
	})
}
