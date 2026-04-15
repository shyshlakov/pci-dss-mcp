package triagescanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestExtractImports(t *testing.T) {
	src := `package foo

import (
	"fmt"
	"os"
	myjson "encoding/json"
)
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}

	imports := extractImports(file)
	if len(imports) != 3 {
		t.Fatalf("expected 3 imports, got %d: %v", len(imports), imports)
	}

	// Should be sorted: "fmt", "myjson encoding/json", "os"
	expected := []string{"fmt", "myjson encoding/json", "os"}
	for i, want := range expected {
		if imports[i] != want {
			t.Errorf("import[%d]: got %q, want %q", i, imports[i], want)
		}
	}
}

func TestExtractImports_NilFile(t *testing.T) {
	imports := extractImports(nil)
	if imports != nil {
		t.Errorf("expected nil for nil file, got: %v", imports)
	}
}

func TestExtractPackageDecls(t *testing.T) {
	src := `package foo

var GlobalVar int
const MaxSize = 100
type Config struct {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}

	decls := extractPackageDecls(file, fset)
	if len(decls) != 3 {
		t.Fatalf("expected 3 decls, got %d: %v", len(decls), decls)
	}

	// Check kind prefixes.
	if decls[0][:3] != "var" {
		t.Errorf("decl[0]: expected 'var' prefix, got: %s", decls[0])
	}
	if decls[1][:5] != "const" {
		t.Errorf("decl[1]: expected 'const' prefix, got: %s", decls[1])
	}
	if decls[2][:4] != "type" {
		t.Errorf("decl[2]: expected 'type' prefix, got: %s", decls[2])
	}
}

func TestExtractPackageDecls_NilFile(t *testing.T) {
	decls := extractPackageDecls(nil, nil)
	if decls != nil {
		t.Errorf("expected nil for nil file, got: %v", decls)
	}
}

func TestExtractImports_BlankImport(t *testing.T) {
	// Blank imports (alias "_") should NOT include the alias.
	src := `package foo

import (
	_ "net/http/pprof"
	"fmt"
)
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}

	imports := extractImports(file)
	if len(imports) != 2 {
		t.Fatalf("expected 2 imports, got %d: %v", len(imports), imports)
	}

	// "_" blank imports should appear without alias prefix.
	found := false
	for _, imp := range imports {
		if imp == "net/http/pprof" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected blank import path without alias, got: %v", imports)
	}
}

func TestClassifyFileLocation(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"foo/test/bar.go", "test directory"},
		{"foo/tests/bar.go", "test directory"},
		{"foo/testing/bar.go", "test directory"},
		{"foo/testdata/bar.go", "testdata directory"},
		{"foo/vendor/bar.go", "vendor directory"},
		{"foo/dev/bar.go", "development directory"},
		{"foo/development/bar.go", "development directory"},
		{"foo/example/bar.go", "examples directory"},
		{"foo/examples/bar.go", "examples directory"},
		{"foo/mock/bar.go", "mocks directory"},
		{"foo/mocks/bar.go", "mocks directory"},
		{"foo/fixture/bar.go", "fixtures directory"},
		{"foo/fixtures/bar.go", "fixtures directory"},
		{"foo/src/bar.go", ""},
		{"main.go", ""},
	}

	for _, tc := range tests {
		got := classifyFileLocation(tc.path)
		if got != tc.want {
			t.Errorf("classifyFileLocation(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// Verify nil ast.File doesn't panic.
func TestExtractImports_NilASTFile(t *testing.T) {
	var f *ast.File
	got := extractImports(f)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
