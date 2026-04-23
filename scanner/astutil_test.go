package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

func TestParseGoFileValid(t *testing.T) {
	t.Parallel()
	// Use walker_test.go as a known valid Go file in the same directory.
	f, fset, err := ParseGoFile("walker_test.go")
	if err != nil {
		t.Fatalf("ParseGoFile failed on valid file: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil ast.File")
	}
	if fset == nil {
		t.Fatal("expected non-nil token.FileSet")
	}
}

func TestParseGoFileInvalid(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bad.go"
	writeFile(t, path, "this is not valid go source {{{")

	_, _, err := ParseGoFile(path)
	if err == nil {
		t.Fatal("expected error for invalid Go source, got nil")
	}
}

func TestParseGoFileNonexistent(t *testing.T) {
	t.Parallel()
	_, _, err := ParseGoFile("/nonexistent/file.go")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestInspectCallsFindsFmtPrintln(t *testing.T) {
	t.Parallel()
	src := `package test
import "fmt"
func main() {
	fmt.Println("hello")
	fmt.Sprintf("world")
}
`
	f, fset := mustParseSource(t, src)
	matches := InspectCalls(f, fset, "fmt.Println")

	if len(matches) != 1 {
		t.Fatalf("expected 1 match for fmt.Println, got %d", len(matches))
	}
	if matches[0].FuncName != "fmt.Println" {
		t.Errorf("expected FuncName 'fmt.Println', got %q", matches[0].FuncName)
	}
}

func TestInspectCallsFindsMultiplePatterns(t *testing.T) {
	t.Parallel()
	src := `package test
import (
	"fmt"
	"log"
)
func main() {
	fmt.Println("hello")
	log.Printf("card: %s", "4111")
}
`
	f, fset := mustParseSource(t, src)
	matches := InspectCalls(f, fset, "fmt.Println", "log.Printf")

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
}

func TestInspectCallsNoMatch(t *testing.T) {
	t.Parallel()
	src := `package test
func main() {
	println("hello")
}
`
	f, fset := mustParseSource(t, src)
	matches := InspectCalls(f, fset, "fmt.Println")

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestInspectStringLiteralsFindsPattern(t *testing.T) {
	t.Parallel()
	src := `package test
var pan = "4111111111111111"
var name = "John Doe"
`
	f, fset := mustParseSource(t, src)
	pat := regexp.MustCompile(`^4\d{15}$`)
	matches := InspectStringLiterals(f, fset, pat)

	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Value != "4111111111111111" {
		t.Errorf("expected value '4111111111111111', got %q", matches[0].Value)
	}
}

func TestInspectStringLiteralsNoMatch(t *testing.T) {
	t.Parallel()
	src := `package test
var name = "John Doe"
`
	f, fset := mustParseSource(t, src)
	pat := regexp.MustCompile(`^4\d{15}$`)
	matches := InspectStringLiterals(f, fset, pat)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

func TestInspectStructFieldsFindsCardNumber(t *testing.T) {
	t.Parallel()
	src := `package test
type Payment struct {
	cardNumber string
	Amount     int
	cvv        string
}
`
	f, fset := mustParseSource(t, src)
	nameMatch := func(name string) bool {
		lower := strings.ToLower(name)
		return lower == "cardnumber" || lower == "cvv"
	}
	matches := InspectStructFields(f, fset, nameMatch)

	if len(matches) != 2 {
		t.Fatalf("expected 2 matches (cardNumber, cvv), got %d", len(matches))
	}

	names := make(map[string]bool)
	for _, m := range matches {
		names[m.Name] = true
	}
	if !names["cardNumber"] {
		t.Error("expected to find field 'cardNumber'")
	}
	if !names["cvv"] {
		t.Error("expected to find field 'cvv'")
	}
}

func TestInspectStructFieldsNoMatch(t *testing.T) {
	t.Parallel()
	src := `package test
type Config struct {
	Host string
	Port int
}
`
	f, fset := mustParseSource(t, src)
	nameMatch := func(name string) bool {
		return strings.ToLower(name) == "cardnumber"
	}
	matches := InspectStructFields(f, fset, nameMatch)

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

// mustParseSource parses inline Go source for testing. Fails the test on error.
func mustParseSource(t *testing.T, src string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "test.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("failed to parse test source: %v", err)
	}
	return f, fset
}
