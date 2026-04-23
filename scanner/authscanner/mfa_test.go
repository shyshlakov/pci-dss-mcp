package authscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestIsDelegationOnlyHandler exercises the helper that teaches
// authscanner to skip MFA enforcement on wrapper handlers whose body is
// a single delegating call to another http.Handler. These wrappers are
// cross-cutting router plumbing; the real handlers live on the embedded
// router and are analyzed separately.
func TestIsDelegationOnlyHandler(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "ServeHTTP field delegation",
			src: `package p
import "net/http"
type H interface{ ServeHTTP(w http.ResponseWriter, r *http.Request) }
type W struct{ r H }
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.r.ServeHTTP(w, r) }`,
			want: true,
		},
		{
			name: "nested selector delegation",
			src: `package p
import "net/http"
type W struct{ a struct{ r http.Handler } }
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.a.r.ServeHTTP(w, r) }`,
			want: true,
		},
		{
			name: "gin ServeHTTP delegation",
			src: `package p
import "net/http"
type G interface{ ServeHTTP(http.ResponseWriter, *http.Request) }
type W struct{ g G }
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.g.ServeHTTP(w, r) }`,
			want: true,
		},
		{
			name: "ServeHTTPC context variant",
			src: `package p
import "net/http"
type CtxHandler interface{ ServeHTTPC(ctx interface{}, w http.ResponseWriter, r *http.Request) }
type W struct{ h CtxHandler }
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.h.ServeHTTPC(nil, w, r) }`,
			want: true,
		},
		{
			name: "embedded Handler selector",
			src: `package p
import "net/http"
type W struct{ Handler http.Handler }
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.Handler.ServeHTTP(w, r) }`,
			want: true,
		},
		{
			name: "multi-statement body not delegation",
			src: `package p
import "net/http"
type W struct{}
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { w.Header().Set("X", "Y"); w.Write([]byte("ok")) }`,
			want: false,
		},
		{
			name: "empty body not delegation",
			src: `package p
import "net/http"
type W struct{}
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) {}`,
			want: false,
		},
		{
			name: "function call not method selector",
			src: `package p
import "net/http"
type W struct{}
func serveIt(w http.ResponseWriter, r *http.Request) {}
func (x *W) ServeHTTP(w http.ResponseWriter, r *http.Request) { serveIt(w, r) }`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "test.go", tt.src, 0)
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			var fn *ast.FuncDecl
			for _, decl := range file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name != nil && fd.Name.Name == "ServeHTTP" && fd.Recv != nil {
					fn = fd
					break
				}
			}
			if fn == nil {
				t.Fatalf("could not locate target ServeHTTP method in source")
			}
			got := isDelegationOnlyHandler(fn.Body)
			if got != tt.want {
				t.Errorf("isDelegationOnlyHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDetectMissingMFA_DelegationFixture mirrors the testdata delegation
// fixture at the unit level. It asserts that a wrapper handler whose
// body is a single delegating ServeHTTP call is NOT flagged with
// AUTH-MISSING-MFA once the skip logic lands. (RED baseline: the
// fixture currently IS flagged; flip to GREEN after the helper is wired
// into checkPaymentHandler.)
func TestDetectMissingMFA_DelegationFixture(t *testing.T) {
	t.Parallel()
	src := `package delegation
import "net/http"
type DispatchRouter interface{ http.Handler }
type Wrapper struct{ inner DispatchRouter }
func (x *Wrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) { x.inner.ServeHTTP(w, r) }
`
	// Path contains /tokens/ so Signal 2 admits the function into the
	// payment-context gate, reproducing the fixture layout.
	path := "testdata/vulnerable-payment-service/internal/tokens/delegation/delegating.go"
	file, fset := parseSource(t, src)
	findings := detectMissingMFA(file, fset, path)
	for _, f := range findings {
		if f.RuleID == "AUTH-MISSING-MFA" {
			t.Errorf("delegation-only Wrapper.ServeHTTP should not fire AUTH-MISSING-MFA; got rule=%s file=%s line=%d", f.RuleID, f.FilePath, f.Line)
		}
	}
}
