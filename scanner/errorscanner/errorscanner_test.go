package errorscanner_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
	"github.com/shyshlakov/pci-dss-mcp/scanner/errorscanner"
)

// --- hasResponseWriterParam tests ---

func TestHasResponseWriterParam(t *testing.T) {
	src := `package test

import "net/http"

func handler(w http.ResponseWriter, r *http.Request) {}
func noWriter(r *http.Request) {}
func plainWriter(w int) {}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	tests := []struct {
		funcName string
		want     bool
	}{
		{"handler", true},
		{"noWriter", false},
		{"plainWriter", false},
	}

	funcMap := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcMap[fn.Name.Name] = fn
		}
	}

	for _, tt := range tests {
		t.Run(tt.funcName, func(t *testing.T) {
			fn, ok := funcMap[tt.funcName]
			if !ok {
				t.Fatalf("function %q not found", tt.funcName)
			}
			if got := errorscanner.HasResponseWriterParam(fn); got != tt.want {
				t.Errorf("HasResponseWriterParam(%q) = %v, want %v", tt.funcName, got, tt.want)
			}
		})
	}
}

// --- detectErrorLeaksInBody tests ---

func TestDetectErrorLeaks_HTTPError(t *testing.T) {
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	err := doWork()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "HandlePayment")
	assertHasFinding(t, findings, "ERR-LEAK-DIRECT", scanner.SeverityCritical)
}

func TestDetectErrorLeaks_FmtFprintf(t *testing.T) {
	src := `package test

import (
	"fmt"
	"net/http"
)

func ProcessCheckout(w http.ResponseWriter, r *http.Request) {
	err := doWork()
	if err != nil {
		fmt.Fprintf(w, "error: %v", err)
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "ProcessCheckout")
	assertHasFinding(t, findings, "ERR-LEAK-FORMAT", scanner.SeverityHigh)
}

func TestDetectErrorLeaks_WriteBytes(t *testing.T) {
	src := `package test

import "net/http"

func HandleRefund(w http.ResponseWriter, r *http.Request) {
	dbErr := doWork()
	if dbErr != nil {
		w.Write([]byte(dbErr.Error()))
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "HandleRefund")
	assertHasFinding(t, findings, "ERR-LEAK-WRITE", scanner.SeverityCritical)
}

func TestDetectErrorLeaks_JsonEncode(t *testing.T) {
	src := `package test

import (
	"encoding/json"
	"net/http"
)

func ProcessTransaction(w http.ResponseWriter, r *http.Request) {
	err := doWork()
	if err != nil {
		json.NewEncoder(w).Encode(err)
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "ProcessTransaction")
	assertHasFinding(t, findings, "ERR-LEAK-ENCODE", scanner.SeverityCritical)
}

func TestDetectErrorLeaks_StaticMessage_NoFinding(t *testing.T) {
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	err := doWork()
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "HandlePayment")
	if len(findings) != 0 {
		t.Errorf("Expected no findings for static message, got %d: %v", len(findings), findings)
	}
}

func TestDetectErrorLeaks_NonStdErrName(t *testing.T) {
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	dbErr := doWork()
	if dbErr != nil {
		http.Error(w, dbErr.Error(), http.StatusInternalServerError)
	}
}

func doWork() error { return nil }
`
	findings := parseAndDetect(t, src, "HandlePayment")
	assertHasFinding(t, findings, "ERR-LEAK-DIRECT", scanner.SeverityCritical)
}

// --- Integration test: ScanWithExclusions ---

func TestErrorScanner_ScanWithExclusions(t *testing.T) {
	// Copy the testdata fixture to a temp dir since the walker excludes
	// directories named "testdata" via DefaultExcludeDirs.
	fixtureSrc := filepath.Join("..", "..", "testdata", "error_violations.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/error_violations.go not found, skipping")
	}

	tmpDir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(tmpDir, "error_violations.go"), srcBytes, 0644); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	s := errorscanner.New()
	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions: %v", err)
	}

	// Should find at least 4 violations (one per pattern).
	if len(result.Findings) < 4 {
		t.Errorf("Expected at least 4 findings, got %d: %v", len(result.Findings), result.Findings)
	}

	// Check all four rule IDs are present.
	ruleIDs := make(map[string]bool)
	for _, f := range result.Findings {
		ruleIDs[f.RuleID] = true
	}
	for _, wantRule := range []string{"ERR-LEAK-DIRECT", "ERR-LEAK-FORMAT", "ERR-LEAK-WRITE", "ERR-LEAK-ENCODE"} {
		if !ruleIDs[wantRule] {
			t.Errorf("Missing expected rule %q in findings", wantRule)
		}
	}

	// Verify non-payment handler HandleUser is excluded: no finding should reference it.
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "HandleUser") {
			t.Errorf("HandleUser is not a payment handler, should not produce findings: %v", f)
		}
	}

	// Verify HandleCardUpdate with static message is excluded.
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "HandleCardUpdate") && f.RuleID != "" {
			// HandleCardUpdate uses a static message -- should not be flagged.
			// But it IS a payment handler (contains "card"), so we only check
			// that it doesn't produce findings because its message is static.
			t.Errorf("HandleCardUpdate uses static message, should not produce findings: %v", f)
		}
	}

	// Verify metadata.
	if result.Metadata.ScannedFiles == 0 {
		t.Error("Expected ScannedFiles > 0")
	}
	if result.Metadata.ScannedLines == 0 {
		t.Error("Expected ScannedLines > 0")
	}
}

func TestErrorScanner_ScanWithExclusions_CleanHandler(t *testing.T) {
	// The clean_handler.go in testdata has a HandlePayment that uses generic error messages.
	fixtureSrc := filepath.Join("..", "..", "testdata", "clean_handler.go")
	srcBytes, err := os.ReadFile(fixtureSrc)
	if err != nil {
		t.Skip("testdata/clean_handler.go not found, skipping")
	}

	tmpDir := t.TempDir()
	if writeErr := os.WriteFile(filepath.Join(tmpDir, "clean_handler.go"), srcBytes, 0644); writeErr != nil {
		t.Fatalf("WriteFile: %v", writeErr)
	}

	s := errorscanner.New()
	result, err := s.ScanWithExclusions(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatalf("ScanWithExclusions: %v", err)
	}

	errFindings := filterErrFindings(result.Findings)
	if len(errFindings) != 0 {
		t.Errorf("Expected zero ERR-LEAK findings for clean handler, got %d: %v", len(errFindings), errFindings)
	}
}

func TestErrorScanner_Name(t *testing.T) {
	s := errorscanner.New()
	if got := s.Name(); got != "error_handling" {
		t.Errorf("Name() = %q, want %q", got, "error_handling")
	}
}

func TestErrorScanner_Requirements(t *testing.T) {
	s := errorscanner.New()
	reqs := s.Requirements()
	if len(reqs) != 1 || reqs[0] != "6.2.4" {
		t.Errorf("Requirements() = %v, want [6.2.4]", reqs)
	}
}

// --- Helper functions ---

func parseAndDetect(t *testing.T, src string, funcName string) []scanner.Finding {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != funcName {
			continue
		}
		return errorscanner.DetectErrorLeaksInBody(fn.Body, fset, "test.go")
	}
	t.Fatalf("function %q not found in source", funcName)
	return nil
}

func assertHasFinding(t *testing.T, findings []scanner.Finding, ruleID string, severity scanner.Severity) {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID && f.Severity == severity {
			return
		}
	}
	t.Errorf("Expected finding with RuleID=%q Severity=%q, got: %v", ruleID, severity, findings)
}

func filterErrFindings(findings []scanner.Finding) []scanner.Finding {
	var result []scanner.Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "ERR-LEAK-") {
			result = append(result, f)
		}
	}
	return result
}
