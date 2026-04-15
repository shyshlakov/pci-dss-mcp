package triagescanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/detector"
)

// MiddlewareEvidence captures a single middleware or route registration call
// found during project-wide discovery.
type MiddlewareEvidence struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	MethodName string   `json:"method_name"` // Use, Group, With, Middleware
	Args       []string `json:"args"`        // argument names/expressions
	RawLine    string   `json:"raw_line"`    // source line for display
}

// middlewarePatterns maps selector method names that indicate middleware registration.
var middlewarePatterns = map[string]bool{
	"Use":        true,
	"Group":      true,
	"With":       true,
	"Middleware": true,
}

// routeRegistrationPatterns maps selector method names for route registration.
var routeRegistrationPatterns = map[string]bool{
	"HandleFunc": true,
	"Handle":     true,
	"Get":        true,
	"Post":       true,
	"Put":        true,
	"Delete":     true,
	"Patch":      true,
	"GET":        true,
	"POST":       true,
	"PUT":        true,
	"DELETE":     true,
	"PATCH":      true,
	"Route":      true,
}

// pathPatterns are substrings in lowercased path segments that trigger file scanning.
var pathPatterns = []string{
	"middleware", "router", "routes", "handler", "server", "app", "main",
}

// discoverMiddleware walks the project directory and finds middleware and route
// registrations in files matching known path patterns or importing HTTP frameworks.
// Results are cached on the TriageEngine via the caller.
func discoverMiddleware(projectPath string, cache fileCache) []MiddlewareEvidence {
	var allEvidence []MiddlewareEvidence

	err := filepath.WalkDir(projectPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible directories
		}
		if d.IsDir() {
			// Skip vendor and hidden directories.
			name := d.Name()
			if name == "vendor" || name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		if !shouldScanFile(path, cache) {
			return nil
		}

		pf, pfErr := getParsedGoFile(cache, path)
		if pfErr != nil {
			slog.Debug("triagescanner: skip file for middleware discovery", "path", path, "err", pfErr)
			return nil
		}

		mwEvidence := findMiddlewareRegistrations(pf.astFile, pf.fset, pf.lines)
		for i := range mwEvidence {
			mwEvidence[i].File = path
		}
		allEvidence = append(allEvidence, mwEvidence...)

		routeEvidence := findRouteRegistrations(pf.astFile, pf.fset, pf.lines)
		for i := range routeEvidence {
			routeEvidence[i].File = path
		}
		allEvidence = append(allEvidence, routeEvidence...)

		return nil
	})
	if err != nil {
		slog.Warn("triagescanner: middleware discovery walk error", "path", projectPath, "err", err)
	}

	return allEvidence
}

// shouldScanFile checks if a file should be scanned for middleware/route discovery.
// Returns true if the file's path matches known patterns or imports an HTTP framework.
func shouldScanFile(path string, cache fileCache) bool {
	// Check path patterns.
	lowerPath := strings.ToLower(path)
	for _, pattern := range pathPatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}

	// Check if file imports HTTP framework.
	pf, err := getParsedGoFile(cache, path)
	if err != nil {
		return false
	}
	fw := detector.DetectFramework(pf.astFile)
	return fw != detector.FrameworkUnknown
}

// findMiddlewareRegistrations finds calls like router.Use(mw), engine.Group("/path", mw),
// etc. in a parsed Go file.
func findMiddlewareRegistrations(file *ast.File, fset *token.FileSet, lines []string) []MiddlewareEvidence {
	var evidence []MiddlewareEvidence

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !middlewarePatterns[sel.Sel.Name] {
			return true
		}

		pos := fset.Position(call.Pos())
		rawLine := ""
		if pos.Line > 0 && pos.Line <= len(lines) {
			rawLine = strings.TrimSpace(lines[pos.Line-1])
		}

		ev := MiddlewareEvidence{
			Line:       pos.Line,
			MethodName: sel.Sel.Name,
			Args:       extractCallArgNames(call),
			RawLine:    rawLine,
		}
		evidence = append(evidence, ev)
		return true
	})

	return evidence
}

// findRouteRegistrations finds calls like router.GET("/path", handler),
// http.HandleFunc("/path", handler), etc.
func findRouteRegistrations(file *ast.File, fset *token.FileSet, lines []string) []MiddlewareEvidence {
	var evidence []MiddlewareEvidence

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !routeRegistrationPatterns[sel.Sel.Name] {
			return true
		}

		pos := fset.Position(call.Pos())
		rawLine := ""
		if pos.Line > 0 && pos.Line <= len(lines) {
			rawLine = strings.TrimSpace(lines[pos.Line-1])
		}

		ev := MiddlewareEvidence{
			Line:       pos.Line,
			MethodName: sel.Sel.Name,
			Args:       extractCallArgNames(call),
			RawLine:    rawLine,
		}
		evidence = append(evidence, ev)
		return true
	})

	return evidence
}

// extractCallArgNames extracts human-readable names from call expression arguments.
// For *ast.Ident: returns the name.
// For *ast.SelectorExpr: returns "X.Sel".
// For *ast.CallExpr: returns the function name (for wrapper patterns).
// For everything else: returns "<expr>".
func extractCallArgNames(call *ast.CallExpr) []string {
	args := make([]string, 0, len(call.Args))
	for _, arg := range call.Args {
		args = append(args, exprName(arg))
	}
	return args
}

// exprName returns a human-readable name for an AST expression.
func exprName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return fmt.Sprintf("%s.%s", ident.Name, e.Sel.Name)
		}
		return e.Sel.Name
	case *ast.CallExpr:
		// Wrapper pattern: mfaRequired(handler)
		switch fn := e.Fun.(type) {
		case *ast.Ident:
			return fn.Name
		case *ast.SelectorExpr:
			if ident, ok := fn.X.(*ast.Ident); ok {
				return fmt.Sprintf("%s.%s", ident.Name, fn.Sel.Name)
			}
			return fn.Sel.Name
		}
		return "<expr>"
	case *ast.BasicLit:
		// String literal: return quoted value.
		return e.Value
	default:
		return "<expr>"
	}
}
