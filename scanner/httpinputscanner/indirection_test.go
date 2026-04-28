package httpinputscanner

import (
	"context"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// TestCentralizedAbortHelper exercises the D-14 heuristic recognizer by
// loading the vulnerable-payment-service fixture's internal/http_input
// package and asking the recognizer about each FuncDecl it knows.
func TestCentralizedAbortHelper(t *testing.T) {
	pkg, ok := loadFixtureHTTPInput(t)
	if !ok {
		return
	}
	tt := []struct {
		funcName string
		fileName string
		want     bool
	}{
		{funcName: "Abort", fileName: "central_abort_log.go", want: true},
		{funcName: "AbortWithErrorLog", fileName: "error_taint.go", want: true},
		{funcName: "parseChargeID", fileName: "error_taint.go", want: false},
		{funcName: "parseMerchantID", fileName: "central_abort_log.go", want: false},
		{funcName: "GetMerchant", fileName: "central_abort_log.go", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.funcName, func(t *testing.T) {
			fn, file := lookupFuncDecl(pkg, tc.fileName, tc.funcName)
			if fn == nil {
				t.Skipf("function %s not found in fixture %s", tc.funcName, tc.fileName)
			}
			got := isCentralizedAbortHelper(fn, file, pkg.TypesInfo)
			if got != tc.want {
				t.Fatalf("isCentralizedAbortHelper(%s) = %v, want %v", tc.funcName, got, tc.want)
			}
		})
	}
}

// TestContextExtractedLogger checks the D-14 / D-16.4 recognizer for
// signature-shape recognition.
func TestContextExtractedLogger(t *testing.T) {
	pkg, ok := loadFixtureHTTPInput(t)
	if !ok {
		return
	}
	t.Run("Abort_is_not_logger_extractor", func(t *testing.T) {
		fn, _ := lookupFuncDecl(pkg, "central_abort_log.go", "Abort")
		if fn == nil {
			t.Skip("Abort not found")
		}
		if isContextExtractedLogger(fn) {
			t.Fatal("Abort should not be recognized as a context-extracted logger")
		}
	})

	// Synthetic positive cases via go/types construction.
	t.Run("synthetic_slog_logger_from_ctx", func(t *testing.T) {
		fn := makeSyntheticContextLoggerFunc(t, "log/slog", "Logger", true)
		if !isContextExtractedLogger(fn) {
			t.Fatal("synthetic CtxLog(*slog.Logger) should be a context-extracted logger")
		}
	})
	t.Run("synthetic_zerolog_logger_from_ctx", func(t *testing.T) {
		fn := makeSyntheticContextLoggerFunc(t, "github.com/rs/zerolog", "Logger", true)
		if !isContextExtractedLogger(fn) {
			t.Fatal("synthetic Ctx(*zerolog.Logger) should be a context-extracted logger")
		}
	})
	t.Run("synthetic_logrus_logger_from_ctx", func(t *testing.T) {
		fn := makeSyntheticContextLoggerFunc(t, "github.com/sirupsen/logrus", "Logger", true)
		if !isContextExtractedLogger(fn) {
			t.Fatal("synthetic LoggerFrom(*logrus.Logger) should be a context-extracted logger")
		}
	})
	t.Run("synthetic_no_ctx_param", func(t *testing.T) {
		fn := makeSyntheticContextLoggerFunc(t, "log/slog", "Logger", false)
		if isContextExtractedLogger(fn) {
			t.Fatal("function without context.Context should NOT match")
		}
	})
	t.Run("synthetic_returns_string_not_logger", func(t *testing.T) {
		fn := makeSyntheticContextStringFunc(t, true)
		if isContextExtractedLogger(fn) {
			t.Fatal("function returning string should NOT match")
		}
	})
}

// TestAbortHelperIntegration runs the full scanner on the fixture root and
// verifies the GREEN-gate-closing pair emits at the contracted line locations.
func TestAbortHelperIntegration(t *testing.T) {
	fixtureRoot, ok := vulnerableFixtureRoot(t)
	if !ok {
		return
	}
	s := New()
	result, err := s.ScanFullWithTaint(context.Background(), fixtureRoot, nil, false, false, true)
	if err != nil {
		t.Fatalf("ScanFullWithTaint: %v", err)
	}
	type loc struct {
		rule string
		file string
		line int
	}
	wants := []loc{
		{rule: "HTTP-INPUT-ERROR", file: "central_abort_log.go", line: 30},
		{rule: "HTTP-INPUT-ERROR", file: "struct_logger_field.go", line: 20},
	}
	for _, w := range wants {
		hit := false
		for _, f := range result.Findings {
			if f.RuleID != w.rule {
				continue
			}
			if !strings.HasSuffix(f.FilePath, w.file) {
				continue
			}
			if absLineDiff(f.Line, w.line) <= 2 {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("expected emission %+v not found", w)
		}
	}
	count := 0
	for _, f := range result.Findings {
		if f.RuleID == "HTTP-INPUT-ERROR" {
			count++
		}
	}
	if count < 7 {
		t.Errorf("HTTP-INPUT-ERROR count = %d, want >= 7", count)
	}
}

// TestNegativeDifferentiatorsStayClean asserts that mask_helper_clears_taint.go
// and route_template_no_taint.go emit ZERO non-INFO HTTP-INPUT-* findings.
func TestNegativeDifferentiatorsStayClean(t *testing.T) {
	fixtureRoot, ok := vulnerableFixtureRoot(t)
	if !ok {
		return
	}
	s := New()
	result, err := s.ScanFullWithTaint(context.Background(), fixtureRoot, nil, false, false, true)
	if err != nil {
		t.Fatalf("ScanFullWithTaint: %v", err)
	}
	clean := []string{"mask_helper_clears_taint.go", "route_template_no_taint.go"}
	for _, f := range result.Findings {
		if !strings.HasPrefix(f.RuleID, "HTTP-INPUT-") {
			continue
		}
		if f.Severity == scanner.SeverityInfo {
			continue
		}
		for _, c := range clean {
			if strings.HasSuffix(f.FilePath, c) {
				t.Errorf("clean file %s emitted %s %s at line %d", c, f.RuleID, f.Severity, f.Line)
			}
		}
	}
}

// loadFixtureHTTPInput loads the internal/http_input fixture package via the
// shared taint engine. Returns false (with t.Skip) when the fixture cannot be
// located - test runs outside the repo skip cleanly.
func loadFixtureHTTPInput(t *testing.T) (*packages.Package, bool) {
	t.Helper()
	root, ok := vulnerableFixtureRoot(t)
	if !ok {
		return nil, false
	}
	engine := taint.GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine could not load fixture")
		return nil, false
	}
	for _, p := range engine.LoadedPackages() {
		if p == nil || p.Types == nil {
			continue
		}
		if strings.HasSuffix(p.PkgPath, "/internal/http_input") {
			return p, true
		}
	}
	t.Skip("internal/http_input package not loaded")
	return nil, false
}

// vulnerableFixtureRoot returns the absolute path to the fixture under test.
func vulnerableFixtureRoot(t *testing.T) (string, bool) {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Skipf("Getwd: %v", err)
		return "", false
	}
	dir := cwd
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "testdata", "vulnerable-payment-service")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				t.Skipf("Abs: %v", err)
				return "", false
			}
			return abs, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("fixture root not located")
	return "", false
}

// lookupFuncDecl finds a FuncDecl by name in a specific file of a package and
// returns the resolved *types.Func plus the *ast.File for body inspection.
func lookupFuncDecl(pkg *packages.Package, fileName, funcName string) (*types.Func, *ast.File) {
	if pkg == nil || pkg.TypesInfo == nil {
		return nil, nil
	}
	for i, file := range pkg.Syntax {
		if i >= len(pkg.GoFiles) {
			break
		}
		if !strings.HasSuffix(pkg.GoFiles[i], fileName) {
			continue
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name == nil {
				continue
			}
			if fd.Name.Name != funcName {
				continue
			}
			obj, _ := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
			if obj == nil {
				continue
			}
			return obj, file
		}
	}
	return nil, nil
}

// makeSyntheticContextLoggerFunc constructs a *types.Func with signature
// `func(ctx context.Context) *<pkg>.<typ>` (or no ctx) for unit-testing the
// recognizer without requiring a full packages.Load.
func makeSyntheticContextLoggerFunc(t *testing.T, pkgPath, typeName string, withCtx bool) *types.Func {
	t.Helper()
	pkg := types.NewPackage(pkgPath, lastSegment(pkgPath))
	loggerName := types.NewTypeName(0, pkg, typeName, nil)
	loggerType := types.NewNamed(loggerName, types.NewStruct(nil, nil), nil)
	results := types.NewTuple(types.NewVar(0, nil, "", types.NewPointer(loggerType)))
	var params *types.Tuple
	if withCtx {
		ctxPkg := types.NewPackage("context", "context")
		ctxName := types.NewTypeName(0, ctxPkg, "Context", nil)
		ctxType := types.NewNamed(ctxName, types.NewInterfaceType(nil, nil), nil)
		params = types.NewTuple(types.NewVar(0, nil, "ctx", ctxType))
	} else {
		params = types.NewTuple()
	}
	sig := types.NewSignatureType(nil, nil, nil, params, results, false)
	return types.NewFunc(0, types.NewPackage("test", "test"), "F", sig)
}

// makeSyntheticContextStringFunc returns `func(ctx context.Context) string`
// used as a negative case for isContextExtractedLogger.
func makeSyntheticContextStringFunc(t *testing.T, withCtx bool) *types.Func {
	t.Helper()
	var params *types.Tuple
	if withCtx {
		ctxPkg := types.NewPackage("context", "context")
		ctxName := types.NewTypeName(0, ctxPkg, "Context", nil)
		ctxType := types.NewNamed(ctxName, types.NewInterfaceType(nil, nil), nil)
		params = types.NewTuple(types.NewVar(0, nil, "ctx", ctxType))
	} else {
		params = types.NewTuple()
	}
	results := types.NewTuple(types.NewVar(0, nil, "", types.Typ[types.String]))
	sig := types.NewSignatureType(nil, nil, nil, params, results, false)
	return types.NewFunc(0, types.NewPackage("test", "test"), "F", sig)
}

func lastSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func absLineDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
