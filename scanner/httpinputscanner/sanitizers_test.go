package httpinputscanner

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"
)

func TestPassthroughLibraryCoverage(t *testing.T) {
	tt := []struct {
		pkg    string
		method string
	}{
		{pkg: "fmt", method: "Sprintf"},
		{pkg: "fmt", method: "Sprint"},
		{pkg: "fmt", method: "Sprintln"},
		{pkg: "fmt", method: "Errorf"},
		{pkg: "errors", method: "Join"},
		{pkg: "github.com/pkg/errors", method: "Wrap"},
		{pkg: "github.com/cockroachdb/errors", method: "WithSafeDetails"},
		{pkg: "github.com/hashicorp/go-multierror", method: "Append"},
		{pkg: "go.uber.org/multierr", method: "Combine"},
		{pkg: "github.com/rotisserie/eris", method: "Wrap"},
		{pkg: "strings", method: "Join"},
		{pkg: "context", method: "WithValue"},
	}
	for _, tc := range tt {
		t.Run(tc.pkg+"."+tc.method, func(t *testing.T) {
			found := false
			for _, spec := range passthroughLibrary {
				if spec.PkgPath == tc.pkg && spec.Method == tc.method {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("passthroughLibrary missing %s.%s", tc.pkg, tc.method)
			}
		})
	}
}

func TestSanitizerNameRegexMatches(t *testing.T) {
	tt := []struct {
		name string
		want bool
	}{
		{name: "Mask", want: true},
		{name: "Maskify", want: true},
		{name: "Redact", want: true},
		{name: "Sanitize", want: true},
		{name: "scrubInput", want: true},
		{name: "obfuscatePAN", want: true},
		{name: "Encode", want: false},
		{name: "Format", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizerNameRegex.MatchString(tc.name)
			if got != tc.want {
				t.Fatalf("sanitizerNameRegex.MatchString(%q) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestPublicMaskPackagePath(t *testing.T) {
	tt := []struct {
		pkg  string
		want bool
	}{
		{pkg: "github.com/foo/mask", want: true},
		{pkg: "github.com/foo/redact", want: true},
		{pkg: "github.com/foo/sanitize", want: true},
		{pkg: "github.com/foo/card", want: true},
		{pkg: "github.com/foo/log", want: false},
		{pkg: "github.com/foo/util", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.pkg, func(t *testing.T) {
			got := isPublicMaskPackagePath(tc.pkg)
			if got != tc.want {
				t.Fatalf("isPublicMaskPackagePath(%q) = %v, want %v", tc.pkg, got, tc.want)
			}
		})
	}
}

func TestEnclosingBlock(t *testing.T) {
	src := `package x
func F() {
	if true {
		_ = 1
	}
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pos := f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.IfStmt).Body.List[0].Pos()
	block := enclosingBlock(f, pos)
	if block == nil {
		t.Fatal("enclosingBlock returned nil for inner assign")
	}
	_ = types.IsInterface
}

func TestFormatValidatorTableCoverage(t *testing.T) {
	tt := []struct {
		pkg    string
		typ    string
		method string
	}{
		{pkg: "github.com/google/uuid", method: "Parse"},
		{pkg: "github.com/google/uuid", method: "MustParse"},
		{pkg: "github.com/google/uuid", method: "ParseBytes"},

		{pkg: "github.com/gofrs/uuid", method: "FromString"},
		{pkg: "github.com/gofrs/uuid", method: "FromBytes"},
		{pkg: "github.com/gofrs/uuid", typ: "UUID", method: "Parse"},

		{pkg: "time", method: "Parse"},
		{pkg: "time", method: "ParseInLocation"},
		{pkg: "time", method: "ParseDuration"},

		{pkg: "strconv", method: "Atoi"},
		{pkg: "strconv", method: "ParseInt"},
		{pkg: "strconv", method: "ParseUint"},
		{pkg: "strconv", method: "ParseFloat"},
		{pkg: "strconv", method: "ParseBool"},

		{pkg: "net", method: "ParseIP"},
		{pkg: "net", method: "ParseCIDR"},

		{pkg: "net/netip", method: "ParseAddr"},
		{pkg: "net/netip", method: "ParseAddrPort"},
		{pkg: "net/netip", method: "ParsePrefix"},

		{pkg: "net/mail", method: "ParseAddress"},
		{pkg: "net/mail", method: "ParseAddressList"},
	}
	for _, tc := range tt {
		t.Run(tc.pkg+"/"+tc.typ+"/"+tc.method, func(t *testing.T) {
			found := false
			for _, spec := range formatValidatorTable {
				if spec.PkgPath == tc.pkg && spec.TypeName == tc.typ && spec.Method == tc.method {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("formatValidatorTable missing %s.%s.%s", tc.pkg, tc.typ, tc.method)
			}
		})
	}
}

func TestFormatValidatorTableExcludesURL(t *testing.T) {
	for _, spec := range formatValidatorTable {
		if spec.PkgPath == "net/url" {
			t.Fatalf("formatValidatorTable must not include net/url entries (found %s.%s)", spec.PkgPath, spec.Method)
		}
	}
}

func TestFormatValidatorTableExcludesGenericConversions(t *testing.T) {
	forbidden := []struct {
		pkg    string
		method string
	}{
		{pkg: "strings", method: "ToLower"},
		{pkg: "strings", method: "TrimSpace"},
		{pkg: "strings", method: "ReplaceAll"},
		{pkg: "regexp", method: "FindString"},
	}
	for _, f := range forbidden {
		for _, spec := range formatValidatorTable {
			if spec.PkgPath == f.pkg && spec.Method == f.method {
				t.Fatalf("formatValidatorTable must not include %s.%s (out of scope)", f.pkg, f.method)
			}
		}
	}
}

func TestIsFormatValidatorSanitizerNilGuards(t *testing.T) {
	if isFormatValidatorSanitizer(nil, nil) {
		t.Fatal("isFormatValidatorSanitizer(nil, nil) returned true")
	}
	info := &types.Info{}
	if isFormatValidatorSanitizer(nil, info) {
		t.Fatal("isFormatValidatorSanitizer(nil, info) returned true")
	}
}

func TestMatchFormatValidatorSynthetic(t *testing.T) {
	tt := []struct {
		name     string
		pkgPath  string
		typeName string
		method   string
		want     bool
	}{
		{name: "google/uuid.Parse", pkgPath: "github.com/google/uuid", method: "Parse", want: true},
		{name: "google/uuid.MustParse", pkgPath: "github.com/google/uuid", method: "MustParse", want: true},
		{name: "google/uuid.ParseBytes", pkgPath: "github.com/google/uuid", method: "ParseBytes", want: true},

		{name: "gofrs/uuid.FromString", pkgPath: "github.com/gofrs/uuid", method: "FromString", want: true},
		{name: "gofrs/uuid.FromBytes", pkgPath: "github.com/gofrs/uuid", method: "FromBytes", want: true},
		{name: "gofrs/uuid.UUID.Parse", pkgPath: "github.com/gofrs/uuid", typeName: "UUID", method: "Parse", want: true},

		{name: "time.Parse", pkgPath: "time", method: "Parse", want: true},
		{name: "time.ParseInLocation", pkgPath: "time", method: "ParseInLocation", want: true},
		{name: "time.ParseDuration", pkgPath: "time", method: "ParseDuration", want: true},

		{name: "strconv.Atoi", pkgPath: "strconv", method: "Atoi", want: true},
		{name: "strconv.ParseInt", pkgPath: "strconv", method: "ParseInt", want: true},
		{name: "strconv.ParseUint", pkgPath: "strconv", method: "ParseUint", want: true},
		{name: "strconv.ParseFloat", pkgPath: "strconv", method: "ParseFloat", want: true},
		{name: "strconv.ParseBool", pkgPath: "strconv", method: "ParseBool", want: true},

		{name: "net.ParseIP", pkgPath: "net", method: "ParseIP", want: true},
		{name: "net.ParseCIDR", pkgPath: "net", method: "ParseCIDR", want: true},

		{name: "net/netip.ParseAddr", pkgPath: "net/netip", method: "ParseAddr", want: true},
		{name: "net/netip.ParseAddrPort", pkgPath: "net/netip", method: "ParseAddrPort", want: true},
		{name: "net/netip.ParsePrefix", pkgPath: "net/netip", method: "ParsePrefix", want: true},

		{name: "net/mail.ParseAddress", pkgPath: "net/mail", method: "ParseAddress", want: true},
		{name: "net/mail.ParseAddressList", pkgPath: "net/mail", method: "ParseAddressList", want: true},

		{name: "negative_url.Parse", pkgPath: "net/url", method: "Parse", want: false},
		{name: "negative_url.ParseRequestURI", pkgPath: "net/url", method: "ParseRequestURI", want: false},
		{name: "negative_strings.ToLower", pkgPath: "strings", method: "ToLower", want: false},
		{name: "negative_strings.TrimSpace", pkgPath: "strings", method: "TrimSpace", want: false},
		{name: "negative_fmt.Sprintf", pkgPath: "fmt", method: "Sprintf", want: false},
		{name: "negative_attacker_uuid_pkg", pkgPath: "github.com/attacker/uuid", method: "Parse", want: false},
		{name: "negative_method_with_unexpected_recv", pkgPath: "github.com/google/uuid", typeName: "Other", method: "Parse", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fn := makeSyntheticFormatValidatorFunc(tc.pkgPath, tc.typeName, tc.method)
			got := matchFormatValidator(fn)
			if got != tc.want {
				t.Fatalf("matchFormatValidator(%s.%s.%s) = %v, want %v", tc.pkgPath, tc.typeName, tc.method, got, tc.want)
			}
		})
	}
}

func TestIsFormatValidatorSanitizerEndToEnd(t *testing.T) {
	src := `package main

import (
	"strconv"
)

func F(s string) {
	_, _ = strconv.Atoi(s)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "p.go", src, 0)
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
	if _, err := conf.Check("main", fset, []*ast.File{f}, info); err != nil {
		t.Skipf("typecheck (env-dependent, fixture-style skip): %v", err)
	}
	var found *ast.CallExpr
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "strconv" && sel.Sel.Name == "Atoi" {
				found = call
				return false
			}
		}
		return true
	})
	if found == nil {
		t.Fatal("could not locate strconv.Atoi call")
	}
	if !isFormatValidatorSanitizer(found, info) {
		t.Fatal("strconv.Atoi(s) call should be recognized as a format-validator sanitizer")
	}
}

func makeSyntheticFormatValidatorFunc(pkgPath, typeName, method string) *types.Func {
	pkg := types.NewPackage(pkgPath, lastSegment(pkgPath))
	var sig *types.Signature
	if typeName != "" {
		recvName := types.NewTypeName(0, pkg, typeName, nil)
		recvType := types.NewNamed(recvName, types.NewStruct(nil, nil), nil)
		recv := types.NewVar(0, pkg, "u", types.NewPointer(recvType))
		sig = types.NewSignatureType(recv, nil, nil, types.NewTuple(), types.NewTuple(), false)
	} else {
		sig = types.NewSignatureType(nil, nil, nil, types.NewTuple(), types.NewTuple(), false)
	}
	return types.NewFunc(0, pkg, method, sig)
}

func TestPassthroughLibraryReceiverProjectors(t *testing.T) {
	want := []struct {
		pkg  string
		typ  string
		meth string
	}{
		{pkg: "bytes", typ: "Buffer", meth: "String"},
		{pkg: "bytes", typ: "Buffer", meth: "Bytes"},
		{pkg: "strings", typ: "Builder", meth: "String"},
	}
	for _, w := range want {
		t.Run(w.pkg+"."+w.typ+"."+w.meth, func(t *testing.T) {
			found := false
			for _, spec := range passthroughLibrary {
				if spec.PkgPath == w.pkg && spec.TypeName == w.typ && spec.Method == w.meth {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("passthroughLibrary missing %s.%s.%s", w.pkg, w.typ, w.meth)
			}
		})
	}
}

func TestReverseFlowSourceArgRecognition(t *testing.T) {
	tt := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "io.Copy(&buf, src) recognized",
			src: `package main
import (
	"bytes"
	"io"
)
func F(r io.Reader) { var buf bytes.Buffer; io.Copy(&buf, r) }
`,
			want: true,
		},
		{
			name: "io.WriteString(&buf, s) recognized",
			src: `package main
import (
	"io"
	"strings"
)
func F() { var b strings.Builder; io.WriteString(&b, "x") }
`,
			want: true,
		},
		{
			name: "io.ReadAll NOT recognized",
			src: `package main
import (
	"io"
)
func F(r io.Reader) ([]byte, error) { return io.ReadAll(r) }
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
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "io" {
						found = call
						return false
					}
				}
				return true
			})
			if found == nil {
				t.Fatal("did not locate io.* call")
			}
			_, _, ok := reverseFlowSourceArg(found, info)
			if ok != tc.want {
				t.Fatalf("reverseFlowSourceArg ok = %v, want %v", ok, tc.want)
			}
		})
	}
}

func TestIsReceiverTypedPassthroughDispatch(t *testing.T) {
	tt := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "buf.String() on bytes.Buffer is receiver-typed passthrough",
			src: `package main
import "bytes"
func F() { var buf bytes.Buffer; _ = buf.String() }
`,
			want: true,
		},
		{
			name: "fmt.Sprintf is NOT receiver-typed passthrough (free fn)",
			src: `package main
import "fmt"
func F() { _ = fmt.Sprintf("x %d", 1) }
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
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					name := sel.Sel.Name
					if name == "String" || name == "Sprintf" {
						found = call
						return false
					}
				}
				return true
			})
			if found == nil {
				t.Fatal("did not locate target call")
			}
			got := isReceiverTypedPassthrough(found, info)
			if got != tc.want {
				t.Fatalf("isReceiverTypedPassthrough = %v, want %v", got, tc.want)
			}
		})
	}
}
