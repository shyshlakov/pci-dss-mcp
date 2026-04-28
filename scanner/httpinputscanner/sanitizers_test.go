package httpinputscanner

import (
	"go/ast"
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
	// The body of the if should be the inner-most block at the position of the
	// inner `_ = 1` assign statement.
	pos := f.Decls[0].(*ast.FuncDecl).Body.List[0].(*ast.IfStmt).Body.List[0].Pos()
	block := enclosingBlock(f, pos)
	if block == nil {
		t.Fatal("enclosingBlock returned nil for inner assign")
	}
	_ = types.IsInterface
}
