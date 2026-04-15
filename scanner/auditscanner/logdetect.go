package auditscanner

import (
	"go/ast"
	"path"
	"strings"
)

// structuredLoggerImports maps import path to default alias for known
// structured logging packages. Used for import alias resolution.
var structuredLoggerImports = map[string]string{
	"log/slog":                      "slog",
	"go.uber.org/zap":               "zap",
	"github.com/rs/zerolog":         "zerolog",
	"github.com/rs/zerolog/log":     "log",
	"github.com/sirupsen/logrus":    "logrus",
	"github.com/hashicorp/go-hclog": "hclog",
	"github.com/apex/log":           "log",
}

// unstructuredLoggerPatterns lists call patterns for unstructured logging.
var unstructuredLoggerPatterns = map[string]bool{
	"fmt.Printf":   true,
	"fmt.Println":  true,
	"fmt.Print":    true,
	"fmt.Fprintf":  true,
	"fmt.Fprintln": true,
	"fmt.Fprint":   true,
	"log.Printf":   true,
	"log.Println":  true,
	"log.Print":    true,
	"log.Fatalf":   true,
	"log.Fatalln":  true,
	"log.Fatal":    true,
}

// structuredLogMethods contains method names commonly used on structured logger
// instances and builder chains (e.g. zap.L().Info(), zerolog log.Info().Msg()).
var structuredLogMethods = map[string]bool{
	"Info":   true,
	"Warn":   true,
	"Error":  true,
	"Debug":  true,
	"Fatal":  true,
	"Panic":  true,
	"Log":    true,
	"With":   true,
	"Msg":    true,
	"Msgf":   true,
	"Infof":  true,
	"Warnf":  true,
	"Errorf": true,
	"Debugf": true,
	"Fatalf": true,
}

// resolveImportAliases builds a map from import path to local alias for a file.
// If the import has an explicit alias, it uses that. Otherwise it uses the
// last segment of the import path (path.Base). Dot imports (".") and blank
// imports ("_") are included as-is.
func resolveImportAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil {
			aliases[importPath] = imp.Name.Name
		} else {
			aliases[importPath] = path.Base(importPath)
		}
	}
	return aliases
}

// callExprName extracts the function call name from a CallExpr.
// Returns patterns like:
// - "pkg.Func" for selector expressions (e.g. slog.Info)
// - "Func" for plain function calls
// - "" for unrecognizable patterns
//
// For chained calls like zap.L().Info(), it recursively resolves the chain
// to find the package prefix.
func callExprName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		switch x := fn.X.(type) {
		case *ast.Ident:
			return x.Name + "." + fn.Sel.Name
		case *ast.CallExpr:
			// Chained call pattern: zap.L().Info(), zerolog.New().Info()
			// Return "prefix.Method" where prefix is the package from inner call.
			prefix := chainedCallPrefix(x)
			if prefix != "" {
				return prefix + "." + fn.Sel.Name
			}
		}
	}
	return ""
}

// chainedCallPrefix resolves the package prefix from a chained call expression.
// For example, in zap.L().Info(), the inner call is zap.L() and the prefix is "zap".
// Supports multi-level chains like log.Info().Str().Msg() by recursing.
func chainedCallPrefix(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		switch x := fn.X.(type) {
		case *ast.Ident:
			return x.Name
		case *ast.CallExpr:
			return chainedCallPrefix(x)
		}
	case *ast.Ident:
		return fn.Name
	}
	return ""
}

// hasStructuredLogging walks a function body and determines if it contains
// structured logging calls and/or unstructured logging calls.
//
// aliases maps import path to local alias for the file.
//
// Returns (hasStructured, hasUnstructured).
func hasStructuredLogging(body *ast.BlockStmt, aliases map[string]string) (bool, bool) {
	var hasStructured, hasUnstructured bool

	// Build a set of effective aliases for structured logger packages.
	structuredAliases := make(map[string]bool, len(structuredLoggerImports))
	for importPath, defaultAlias := range structuredLoggerImports {
		if alias, ok := aliases[importPath]; ok {
			structuredAliases[alias] = true
		} else {
			structuredAliases[defaultAlias] = true
		}
	}

	// Also track which aliases are for unstructured "log" (stdlib) vs structured
	// packages that also alias to "log".
	stdlogAlias := "log"
	if alias, ok := aliases["log"]; ok {
		stdlogAlias = alias
	}

	// Check if "log" alias is claimed by a structured logger.
	logIsStructured := false
	for importPath := range structuredLoggerImports {
		if alias, ok := aliases[importPath]; ok && alias == stdlogAlias {
			logIsStructured = true
			break
		}
		// Also check if the structured logger's default alias is "log" and
		// the import path is present.
		if _, ok := aliases[importPath]; ok {
			defaultAlias := structuredLoggerImports[importPath]
			if defaultAlias == "log" {
				logIsStructured = true
				break
			}
		}
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		name := callExprName(call)
		if name == "" {
			return true
		}

		// Check structured loggers: name has prefix "alias."
		parts := strings.SplitN(name, ".", 2)
		if len(parts) == 2 {
			pkg := parts[0]
			method := parts[1]
			if structuredAliases[pkg] && structuredLogMethods[method] {
				// Make sure it's not actually stdlib "log" being misidentified.
				if pkg == stdlogAlias && !logIsStructured {
					// This is stdlib log, check if it's in unstructured patterns.
					if unstructuredLoggerPatterns[name] {
						hasUnstructured = true
					}
				} else {
					hasStructured = true
				}
				return true
			}
		}

		// Check unstructured patterns.
		if unstructuredLoggerPatterns[name] {
			hasUnstructured = true
		}

		return true
	})

	return hasStructured, hasUnstructured
}

// sameFileFuncs builds a map of all top-level function declarations in a file
// indexed by function name. Used for 1-level same-file call resolution.
func sameFileFuncs(file *ast.File) map[string]*ast.FuncDecl {
	funcs := make(map[string]*ast.FuncDecl)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		// Only include package-level functions (not methods).
		if fn.Recv == nil {
			funcs[fn.Name.Name] = fn
		}
	}
	return funcs
}

// hasStructuredLoggingInDelegates walks a function body looking for plain
// function calls (no package prefix), looks up each in fileFuncs, and checks
// if any delegate function has structured logging. Returns true on first match.
func hasStructuredLoggingInDelegates(body *ast.BlockStmt, fileFuncs map[string]*ast.FuncDecl, aliases map[string]string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		// Only plain function calls (no selector).
		ident, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		// Look up the function in same-file functions.
		fn, exists := fileFuncs[ident.Name]
		if !exists || fn.Body == nil {
			return true
		}
		hasStruct, _ := hasStructuredLogging(fn.Body, aliases)
		if hasStruct {
			found = true
			return false
		}
		return true
	})
	return found
}
