package triagescanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// ensureMiddlewareDiscovered runs middleware discovery once per project and caches
// the results on the TriageEngine. Subsequent calls return cached results.
func ensureMiddlewareDiscovered(e *TriageEngine, projectPath string) {
	if e.projectScanned {
		return
	}
	allEvidence := discoverMiddleware(projectPath, e.cache)

	// Separate middleware registrations from route registrations.
	for _, ev := range allEvidence {
		if middlewarePatterns[ev.MethodName] {
			e.middlewareCache = append(e.middlewareCache, ev)
		} else if routeRegistrationPatterns[ev.MethodName] {
			e.routeCache = append(e.routeCache, ev)
		}
	}
	e.projectScanned = true
}

// collectAuditContext populates audit-specific context: middleware chain
// (filtered for logging-related middleware) and router setup.
func collectAuditContext(e *TriageEngine, projectPath string, f scanner.Finding, absPath string, ctx *FindingContext) {
	ensureMiddlewareDiscovered(e, projectPath)

	// Filter middleware for logging-related args.
	logKeywords := []string{"log", "audit", "trace", "record"}
	ctx.MiddlewareChain = filterMiddlewareByKeywords(e.middlewareCache, logKeywords)

	// Find route registrations referencing the handler from the finding.
	handlerName := extractHandlerNameFromDescription(f.Description)
	if handlerName != "" {
		for _, route := range e.routeCache {
			if routeReferencesHandler(route, handlerName) {
				ctx.RouterSetup = route.RawLine
				break
			}
		}
	}

	// Evidence files.
	ctx.EvidenceFiles = collectEvidenceFiles(e.middlewareCache, e.routeCache)
}

// collectCSPContext populates CSP-specific context: response type detection
// and CSP-related middleware evidence.
func collectCSPContext(e *TriageEngine, projectPath string, f scanner.Finding, absPath string, ctx *FindingContext) {
	ensureMiddlewareDiscovered(e, projectPath)

	// Detect response type from the enclosing function.
	ctx.ResponseType = detectResponseTypeFromFile(e.cache, absPath, f.Line)

	// Filter middleware for CSP/security-related args.
	cspKeywords := []string{"csp", "security", "helmet", "header"}
	ctx.MiddlewareChain = filterMiddlewareByKeywords(e.middlewareCache, cspKeywords)

	// Evidence files.
	ctx.EvidenceFiles = collectEvidenceFiles(e.middlewareCache, nil)
}

// collectMFAContext populates MFA-specific context: route registration for
// the finding's handler, auth/MFA middleware evidence, project-wide MFA keyword
// search, no-MFA note, and suppression hint.
func collectMFAContext(e *TriageEngine, projectPath string, f scanner.Finding, absPath string, ctx *FindingContext) {
	ensureMiddlewareDiscovered(e, projectPath)

	// Extract handler name from finding description.
	handlerName := extractHandlerNameFromDescription(f.Description)

	// Find route registrations for this handler (: route path + method).
	if handlerName != "" {
		for _, route := range e.routeCache {
			if routeReferencesHandler(route, handlerName) {
				ctx.RouterSetup = route.RawLine
				break
			}
		}
	}

	// Filter middleware for auth/MFA-related args (: middleware chain).
	mfaKW := []string{"mfa", "auth", "2fa", "totp", "otp"}
	ctx.MiddlewareChain = filterMiddlewareByKeywords(e.middlewareCache, mfaKW)

	// Project-wide MFA keyword presence.
	hasMFA := projectHasMFAKeywords(e.cache, projectPath)
	if !hasMFA {
		// No MFA implementation found in codebase.
		ctx.TriageNotes = append(ctx.TriageNotes,
			"No MFA implementation found in codebase. If enforced at infrastructure level, "+
				"use `// pci-ignore: MFA enforced at API gateway -- [gateway name]`")
	}

	// Reference suppression path in triage hint.
	ctx.TriageNotes = append(ctx.TriageNotes,
		"To suppress: add `// pci-ignore: <reason>` on the route registration line. "+
			"Finding moves to SUPPRESSED status in report (visible to QSA).")

	// Evidence files (: import list already in generic context).
	ctx.EvidenceFiles = collectEvidenceFiles(e.middlewareCache, e.routeCache)
}

// mfaProjectKeywords are substrings searched project-wide to detect MFA presence.
var mfaProjectKeywords = []string{"totp", "mfa", "2fa", "otp", "second_factor"}

// projectHasMFAKeywords searches all.go files in projectPath for MFA-related
// keywords. Returns true if any MFA keyword is found anywhere in the project.
func projectHasMFAKeywords(cache fileCache, projectPath string) bool {
	cfg := scanner.WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: []string{"vendor/", "testdata/"},
	}
	for path, err := range scanner.WalkFiles(projectPath, cfg) {
		if err != nil {
			continue
		}
		lines, readErr := getFileLines(cache, path)
		if readErr != nil {
			continue
		}
		for _, line := range lines {
			lower := strings.ToLower(line)
			for _, kw := range mfaProjectKeywords {
				if strings.Contains(lower, kw) {
					return true
				}
			}
		}
	}
	return false
}

// collectSecretsContext populates secrets-specific context: declaration scope
// (const/var/func/package), runtime value indicators, and file location.
func collectSecretsContext(e *TriageEngine, projectPath string, f scanner.Finding, absPath string, ctx *FindingContext) {
	// Non-Go files (.env,.yaml,.json,.toml) get simple scope classification.
	ext := strings.ToLower(filepath.Ext(absPath))
	if ext != ".go" {
		ctx.DeclarationScope = "config file"
		return
	}

	pf, err := getParsedGoFile(e.cache, absPath)
	if err != nil {
		return
	}

	// Determine declaration scope.
	declType, scopeName := findEnclosingDecl(pf.astFile, pf.fset, f.Line)
	switch declType {
	case "const":
		ctx.DeclarationScope = "const block"
	case "var":
		ctx.DeclarationScope = "var block"
	case "func":
		ctx.DeclarationScope = "function scope: " + scopeName
	default:
		ctx.DeclarationScope = "package level"
	}

	// Check surrounding lines for runtime value indicators.
	runtimePatterns := []string{"os.Getenv", "os.LookupEnv", "viper.Get", "cfg.Get", "config.Get", "env.Get"}
	startLine := f.Line - 5
	if startLine < 1 {
		startLine = 1
	}
	endLine := f.Line + 5
	if endLine > len(pf.lines) {
		endLine = len(pf.lines)
	}

	for lineNum := startLine; lineNum <= endLine; lineNum++ {
		if lineNum < 1 || lineNum > len(pf.lines) {
			continue
		}
		line := pf.lines[lineNum-1]
		for _, pattern := range runtimePatterns {
			if strings.Contains(line, pattern) {
				indicator := fmt.Sprintf("Runtime value indicator at line %d: %s", lineNum, strings.TrimSpace(line))
				ctx.EvidenceFiles = append(ctx.EvidenceFiles, indicator)
			}
		}
	}
}

// findEnclosingDecl determines the declaration context of a given source line.
// Returns (declType, scopeName) where declType is "const"/"var"/"func"/"package"
// and scopeName is the function name when declType is "func".
func findEnclosingDecl(file *ast.File, fset *token.FileSet, line int) (string, string) {
	for _, decl := range file.Decls {
		start := fset.Position(decl.Pos()).Line
		end := fset.Position(decl.End()).Line
		if line < start || line > end {
			continue
		}

		switch d := decl.(type) {
		case *ast.GenDecl:
			return d.Tok.String(), ""
		case *ast.FuncDecl:
			name := ""
			if d.Name != nil {
				name = d.Name.Name
			}
			return "func", name
		}
	}
	return "package", ""
}

// filterMiddlewareByKeywords filters middleware evidence returning arg names
// that match any of the given keywords (case-insensitive).
func filterMiddlewareByKeywords(middleware []MiddlewareEvidence, keywords []string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, ev := range middleware {
		for _, arg := range ev.Args {
			lowerArg := strings.ToLower(arg)
			for _, kw := range keywords {
				if strings.Contains(lowerArg, kw) && !seen[arg] {
					result = append(result, arg)
					seen[arg] = true
					break
				}
			}
		}
		// Also check method+args combination for Group("path", middleware).
		if ev.MethodName == "Group" && len(ev.Args) > 1 {
			for _, arg := range ev.Args[1:] {
				lowerArg := strings.ToLower(arg)
				for _, kw := range keywords {
					if strings.Contains(lowerArg, kw) && !seen[arg] {
						result = append(result, arg)
						seen[arg] = true
						break
					}
				}
			}
		}
	}

	return result
}

// extractHandlerNameFromDescription extracts a handler or route name from a
// finding description. Tries common patterns in finding descriptions.
func extractHandlerNameFromDescription(desc string) string {
	// Pattern: "on payment route /path"
	if idx := strings.Index(desc, "payment route "); idx >= 0 {
		after := desc[idx+len("payment route "):]
		return strings.Fields(after)[0]
	}

	// Pattern: "handler handleName" or "handler handleName."
	if idx := strings.Index(desc, "handler "); idx >= 0 {
		after := desc[idx+len("handler "):]
		name := strings.Fields(after)[0]
		// Trim trailing punctuation.
		name = strings.TrimRight(name, ".,;:")
		return name
	}

	// Pattern: "on payment handler handleName"
	if idx := strings.Index(desc, "payment handler "); idx >= 0 {
		after := desc[idx+len("payment handler "):]
		name := strings.Fields(after)[0]
		name = strings.TrimRight(name, ".,;:")
		return name
	}

	return ""
}

// routeReferencesHandler checks if a route registration evidence references
// the given handler name in its arguments.
func routeReferencesHandler(route MiddlewareEvidence, handlerName string) bool {
	for _, arg := range route.Args {
		// Exact match or partial match for wrapped handlers.
		if arg == handlerName || strings.Contains(arg, handlerName) {
			return true
		}
	}
	// Also check raw line as fallback.
	return strings.Contains(route.RawLine, handlerName)
}

// collectEvidenceFiles returns unique file:line references from evidence lists.
func collectEvidenceFiles(middleware, routes []MiddlewareEvidence) []string {
	seen := make(map[string]bool)
	var files []string

	for _, ev := range middleware {
		ref := fmt.Sprintf("%s:%d", ev.File, ev.Line)
		if !seen[ref] {
			seen[ref] = true
			files = append(files, ref)
		}
	}
	for _, ev := range routes {
		ref := fmt.Sprintf("%s:%d", ev.File, ev.Line)
		if !seen[ref] {
			seen[ref] = true
			files = append(files, ref)
		}
	}

	return files
}

// detectResponseTypeFromFile detects the response type of the function
// containing the given line in the specified file.
func detectResponseTypeFromFile(cache fileCache, absPath string, line int) string {
	if !strings.HasSuffix(absPath, ".go") {
		return "unknown"
	}

	pf, err := getParsedGoFile(cache, absPath)
	if err != nil {
		return "unknown"
	}

	fn := findEnclosingFunc(pf.astFile, pf.fset, line)
	if fn == nil || fn.Body == nil {
		return "unknown"
	}

	// Check for JSON response indicators.
	if hasJSONResponse(fn.Body) {
		return "application/json"
	}

	// Check for HTML/template response indicators.
	if hasHTMLResponse(fn.Body) {
		return "text/html"
	}

	// Check string literals for Content-Type.
	contentType := findContentTypeLiteral(fn.Body)
	if contentType != "" {
		return contentType
	}

	return "unknown"
}

// hasJSONResponse checks if a function body contains JSON response patterns.
func hasJSONResponse(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := sel.X.(*ast.Ident); ok {
			if ident.Name == "json" {
				switch sel.Sel.Name {
				case "NewEncoder", "Marshal", "MarshalIndent":
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// hasHTMLResponse checks if a function body contains HTML template response patterns.
func hasHTMLResponse(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Execute", "ExecuteTemplate":
			// Check if the receiver hints at template.
			if ident, ok := sel.X.(*ast.Ident); ok {
				name := strings.ToLower(ident.Name)
				if name == "template" || strings.Contains(name, "tmpl") ||
					strings.Contains(name, "tpl") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// findContentTypeLiteral searches a function body for string literals containing
// "application/json" or "text/html".
func findContentTypeLiteral(body *ast.BlockStmt) string {
	var result string
	ast.Inspect(body, func(n ast.Node) bool {
		if result != "" {
			return false
		}
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		val := strings.Trim(lit.Value, `"`+"`")
		lower := strings.ToLower(val)
		if strings.Contains(lower, "application/json") {
			result = "application/json"
			return false
		}
		if strings.Contains(lower, "text/html") {
			result = "text/html"
			return false
		}
		return true
	})
	return result
}

// findEnclosingFunc returns the FuncDecl containing the given line, or nil.
func findEnclosingFunc(file *ast.File, fset *token.FileSet, line int) *ast.FuncDecl {
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.Position(fn.Pos()).Line
		end := fset.Position(fn.End()).Line
		if line >= start && line <= end {
			return fn
		}
	}
	return nil
}
