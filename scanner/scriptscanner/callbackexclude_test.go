package scriptscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseInline parses a Go source string and returns the *ast.File plus
// the first top-level *ast.FuncDecl matching funcName.
func parseInline(t *testing.T, src, funcName string) (*ast.File, *ast.FuncDecl) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "inline.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		if fn.Name.Name == funcName {
			return file, fn
		}
	}
	t.Fatalf("function %q not found in source", funcName)
	return nil, nil
}

// TestIsServerToServerCallback_NameSuffix verifies rule 1: handler function
// name ending in "Callback" (case-insensitive) qualifies.
func TestIsServerToServerCallback_NameSuffix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		src      string
		funcName string
		path     string
		want     bool
	}{
		{
			name: "MastercardCallback suffix matches",
			src: `package mastercard

import "net/http"

func MastercardCallback(w http.ResponseWriter, r *http.Request) {}
`,
			funcName: "MastercardCallback",
			path:     "pkg/mastercard/handler.go",
			want:     true,
		},
		{
			name: "VisaCallback suffix matches",
			src: `package visa

import "net/http"

func VisaCallback(w http.ResponseWriter, r *http.Request) {}
`,
			funcName: "VisaCallback",
			path:     "pkg/visa/handler.go",
			want:     true,
		},
		{
			name: "handleCallback lowercase suffix matches",
			src: `package x

import "net/http"

func handleCallback(w http.ResponseWriter, r *http.Request) {}
`,
			funcName: "handleCallback",
			path:     "pkg/x/handler.go",
			want:     true,
		},
		{
			name: "PaymentHandler does not match",
			src: `package payment

import "net/http"

func PaymentHandler(w http.ResponseWriter, r *http.Request) {}
`,
			funcName: "PaymentHandler",
			path:     "pkg/payment/handler.go",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, fn := parseInline(t, tt.src, tt.funcName)
			got := isServerToServerCallback(fn, file, tt.path)
			if got != tt.want {
				t.Errorf("isServerToServerCallback(%s) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

// TestIsServerToServerCallback_RoutePath verifies rule 2: handler registered
// on a route path containing "/callback/".
func TestIsServerToServerCallback_RoutePath(t *testing.T) {
	t.Parallel()
	src := `package api

import "net/http"

func RegisterRoutes(router *Router) {
	router.POST("/callback/mastercard", MastercardHandler)
}

func MastercardHandler(w http.ResponseWriter, r *http.Request) {}

type Router struct{}

func (r *Router) POST(path string, h http.HandlerFunc) {}
`
	file, fn := parseInline(t, src, "MastercardHandler")
	got := isServerToServerCallback(fn, file, "pkg/api/handler.go")
	if !got {
		t.Errorf("expected route-path rule to match MastercardHandler registered on /callback/mastercard")
	}
}

// TestIsServerToServerCallback_RoutePathSelector verifies rule 2 with a
// method-value reference (h.Process) rather than bare identifier.
func TestIsServerToServerCallback_RoutePathSelector(t *testing.T) {
	t.Parallel()
	src := `package api

import "net/http"

type Router struct{}

func (r *Router) POST(path string, h http.HandlerFunc) {}

type Handler struct{}

func (h *Handler) Process(w http.ResponseWriter, r *http.Request) {}

func Register(router *Router, h *Handler) {
	router.POST("/callback/visa", h.Process)
}
`
	file, fn := parseInline(t, src, "Process")
	got := isServerToServerCallback(fn, file, "pkg/api/handler.go")
	if !got {
		t.Errorf("expected selector-method Process registered on /callback/visa to match")
	}
}

// TestIsServerToServerCallback_FileInCallbackDir verifies rule 3: file path
// contains a "callback/" directory segment.
func TestIsServerToServerCallback_FileInCallbackDir(t *testing.T) {
	t.Parallel()
	src := `package callback

import "net/http"

func Process(w http.ResponseWriter, r *http.Request) {}
`
	file, fn := parseInline(t, src, "Process")
	got := isServerToServerCallback(fn, file, "internal/http/handler/callback/provider.go")
	if !got {
		t.Errorf("expected file in callback/ dir to match regardless of handler name")
	}
}

// TestIsServerToServerCallback_Negative verifies none-of-the-three case.
func TestIsServerToServerCallback_Negative(t *testing.T) {
	t.Parallel()
	src := `package pay

import "net/http"

func RegisterRoutes(router *Router) {
	router.POST("/pay", PayHandler)
}

func PayHandler(w http.ResponseWriter, r *http.Request) {}

type Router struct{}

func (r *Router) POST(path string, h http.HandlerFunc) {}
`
	file, fn := parseInline(t, src, "PayHandler")
	got := isServerToServerCallback(fn, file, "internal/http/handler/pay.go")
	if got {
		t.Errorf("expected PayHandler at /pay to NOT match (none of 3 rules apply)")
	}
}

// TestIsServerToServerCallback_PartialMatchNotEnough verifies that
// "HandleCallbacks" (plural, ends with "callbacks") does NOT match — per
// the rule is HasSuffix "callback" exactly.
func TestIsServerToServerCallback_PartialMatchNotEnough(t *testing.T) {
	t.Parallel()
	src := `package x

import "net/http"

func HandleCallbacks(w http.ResponseWriter, r *http.Request) {}
`
	file, fn := parseInline(t, src, "HandleCallbacks")
	got := isServerToServerCallback(fn, file, "pkg/x/handler.go")
	if got {
		t.Errorf("expected HandleCallbacks (plural) to NOT match name-suffix rule")
	}
}
