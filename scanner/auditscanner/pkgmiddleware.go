// Package auditscanner -- cross-file middleware chain resolution.
//
// This file implements through from planning:
// two-pass package-level analysis to detect logging middleware registered
// in sibling files, cross-package import resolution, and caching.
package auditscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// packageMiddlewareCtx stores the parsed middleware context for a single package directory.
type packageMiddlewareCtx struct {
	// groupCoverage maps group identifier name -> true if the group has logger middleware.
	groupCoverage map[string]bool
	// handlerGroups maps handler func name -> group identifier it was registered on.
	handlerGroups map[string]string
	// parentGroup maps child group ident -> parent group ident.
	parentGroup map[string]string
	// installRoutesGroups records groups that had.InstallRoutes() calls — even if the
	// method body is in a child package and can't be resolved locally. Used by
	// parentHasMiddlewareCoveringChild to detect cross-package handler wiring.
	installRoutesGroups map[string]bool
}

// pkgMiddlewareCache stores parsed middleware context per package directory.
// Protected by pkgMiddlewareMu for concurrent safety.
var (
	pkgMiddlewareMu    sync.Mutex
	pkgMiddlewareCache = map[string]*packageMiddlewareCtx{}
)

// ResetPackageCache clears the cross-file middleware cache between scan sessions.
func ResetPackageCache() {
	pkgMiddlewareMu.Lock()
	pkgMiddlewareCache = map[string]*packageMiddlewareCtx{}
	pkgMiddlewareMu.Unlock()
}

// trustedPackageSegments are import path segments that trigger the heuristic
// trust for external packages. If any segment (case-insensitive) matches, the
// package is assumed to install logging middleware.
var trustedPackageSegments = []string{
	"middleware", "logging", "observability", "telemetry", "log", "logger",
}

// maxParentWalk limits how many parent directories we walk up looking for
// middleware registration. Prevents traversing to filesystem root.
const maxParentWalk = 5

// hasLoggingCoverageInPackage checks whether handlerFuncName in the package
// containing targetPath is covered by logging middleware registered in any
// sibling file within the same package directory, OR in a parent directory
// that imports the handler's package and wires it with middleware.
//
// This is the fallback path called only when the per-file hasLoggingMiddleware
// returns false. It performs a two-pass package-level analysis:
//
//	Pass A: extract group definitions, middleware registrations, handler-group bindings
//	Pass B: check if the handler's group (or any ancestor) has logging coverage
//
// If the handler's own package has no coverage, walks up parent directories
// (up to maxParentWalk levels) looking for a parent Go package that imports
// the handler package and registers middleware on groups that the handler
// is bound to via InstallRoutes.
func hasLoggingCoverageInPackage(targetPath, handlerFuncName string) bool {
	pkgDir := filepath.Dir(targetPath)

	// Step 1: Check handler's own package.
	ctx := getOrBuildCtx(pkgDir)
	if ctx != nil {
		if groupIdent, ok := ctx.handlerGroups[handlerFuncName]; ok {
			if groupHasCoverage(ctx, groupIdent) {
				return true
			}
		}
	}

	// Step 2: Walk up parent directories looking for middleware wiring.
	// is in a parent package (handler/) while payment handlers live in child
	// packages (handler/tokens/v1/, handler/callback/).
	childPkg := pkgDir
	current := pkgDir
	for i := 0; i < maxParentWalk; i++ {
		parent := filepath.Dir(current)
		if parent == current {
			break // reached filesystem root
		}
		parentCtx := getOrBuildCtx(parent)
		if parentCtx != nil && parentHasMiddlewareCoveringChild(parentCtx, childPkg) {
			return true
		}
		current = parent
	}

	return false
}

// getOrBuildCtx returns the cached package middleware context or builds one.
func getOrBuildCtx(pkgDir string) *packageMiddlewareCtx {
	pkgMiddlewareMu.Lock()
	ctx, cached := pkgMiddlewareCache[pkgDir]
	pkgMiddlewareMu.Unlock()

	if !cached {
		ctx = buildPackageMiddlewareCtx(pkgDir)
		pkgMiddlewareMu.Lock()
		pkgMiddlewareCache[pkgDir] = ctx
		pkgMiddlewareMu.Unlock()
	}
	return ctx
}

// parentHasMiddlewareCoveringChild checks if the parent package has logging
// middleware on ANY group that also has an InstallRoutes call wiring child
// package handlers. This handles the common pattern:
//
//	// handler/handler.go (parent package)
//	middleware.Install(apiV1Group) // ← logger middleware on group
//	tokensHV1.InstallRoutes(apiV1Group) // ← wires child package handlers to same group
func parentHasMiddlewareCoveringChild(ctx *packageMiddlewareCtx, childPkgDir string) bool {
	// Check if ANY group has BOTH middleware coverage AND InstallRoutes calls.
	// InstallRoutes wires child package handlers to the group — if the group
	// has middleware, all handlers registered through it inherit coverage.
	for groupIdent, covered := range ctx.groupCoverage {
		if !covered {
			continue
		}
		// Direct match: InstallRoutes called with this exact group.
		if ctx.installRoutesGroups[groupIdent] {
			return true
		}
		// Ancestor match: InstallRoutes called with a child group whose
		// parent chain leads to this covered group.
		for irGroup := range ctx.installRoutesGroups {
			if isAncestorGroup(ctx, irGroup, groupIdent) {
				return true
			}
		}
	}
	return false
}

// isAncestorGroup checks if ancestorIdent is a parent of childIdent via the
// parentGroup chain.
func isAncestorGroup(ctx *packageMiddlewareCtx, childIdent, ancestorIdent string) bool {
	visited := map[string]bool{}
	current := childIdent
	for current != "" && !visited[current] {
		if current == ancestorIdent {
			return true
		}
		visited[current] = true
		current = ctx.parentGroup[current]
	}
	return false
}

// groupHasCoverage walks the parent chain of groupIdent checking for logging coverage.
// Prevents infinite loops with a visited set.
func groupHasCoverage(ctx *packageMiddlewareCtx, groupIdent string) bool {
	visited := map[string]bool{}
	current := groupIdent
	for current != "" && !visited[current] {
		visited[current] = true
		if ctx.groupCoverage[current] {
			return true
		}
		current = ctx.parentGroup[current]
	}
	return false
}

// installRoutesCall records a call to <receiver>.InstallRoutes(<groupArg>)
// found during Pass A, so that Pass B can resolve method bodies.
type installRoutesCall struct {
	receiverIdent string // e.g. "tokensHV1"
	groupArg      string // e.g. "apiV1Group"
}

// methodKey identifies a method by its receiver type and method name.
type methodKey struct {
	typeName   string
	methodName string
}

// buildPackageMiddlewareCtx parses all.go files in pkgDir and builds a
// package-level middleware context.
func buildPackageMiddlewareCtx(pkgDir string) *packageMiddlewareCtx {
	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, pkgDir)
	if len(pkgFiles) == 0 {
		return nil
	}

	ctx := &packageMiddlewareCtx{
		groupCoverage:       make(map[string]bool),
		handlerGroups:       make(map[string]string),
		parentGroup:         make(map[string]string),
		installRoutesGroups: make(map[string]bool),
	}

	// Collect all files and their imports across all packages in the directory.
	type fileInfo struct {
		file    *ast.File
		imports map[string]string // alias -> importPath
	}
	var allFiles []fileInfo

	// Also collect method declarations for InstallRoutes-style resolution.
	// methodBodies maps (receiverTypeName, methodName) -> *ast.FuncDecl
	methodBodies := map[methodKey]*ast.FuncDecl{}

	// Collect InstallRoutes calls for Pass B resolution.
	var irCalls []installRoutesCall

	for _, file := range pkgFiles {
		// Build import map for this file.
		imports := make(map[string]string)
		for _, imp := range file.Imports {
			if imp.Path == nil {
				continue
			}
			importPath := strings.Trim(imp.Path.Value, `"`)
			alias := filepath.Base(importPath) // default alias
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			imports[alias] = importPath
		}
		allFiles = append(allFiles, fileInfo{file: file, imports: imports})

		// Index method declarations.
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Recv == nil || fn.Body == nil {
				continue
			}
			if len(fn.Recv.List) != 1 {
				continue
			}
			typeName := receiverTypeName(fn.Recv.List[0].Type)
			if typeName != "" {
				methodBodies[methodKey{typeName: typeName, methodName: fn.Name.Name}] = fn
			}
		}
	}

	// Pass A: Walk each file for group definitions, middleware, direct handler registrations.
	for _, fi := range allFiles {
		passA(ctx, fi.file, fi.imports, pkgDir, &irCalls)
	}

	// Pass B: Resolve InstallRoutes method bodies.
	// For each call like tokensHV1.InstallRoutes(apiV1Group), find the method body
	// and process it with parameter-to-argument mapping.
	for _, irc := range irCalls {
		resolveInstallRoutesBody(ctx, irc, methodBodies)
	}

	return ctx
}

// receiverTypeName extracts the type name from a method receiver type expression.
// Handles both *T and T forms.
func receiverTypeName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.StarExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name
		}
	case *ast.Ident:
		return e.Name
	}
	return ""
}

// parsePkgFiles reads all non-test .go files from dir and parses them,
// returning the parsed files. Replaces the deprecated parser.ParseDir API
// while preserving the same semantics (skip _test.go, skip subdirectories).
// Individual parse errors are skipped so one malformed file doesn't block
// the whole package.
func parsePkgFiles(fset *token.FileSet, dir string) []*ast.File {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var files []*ast.File
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			continue
		}
		files = append(files, file)
	}
	return files
}

// passA walks a single file's AST extracting group definitions, middleware
// registrations, and handler-group bindings. Collects InstallRoutes calls
// into irCalls for later resolution.
func passA(ctx *packageMiddlewareCtx, file *ast.File, imports map[string]string, pkgDir string, irCalls *[]installRoutesCall) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			handleAssignment(ctx, node)
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				handleCall(ctx, call, imports, pkgDir, irCalls)
			}
		}
		return true
	})
}

// handleAssignment processes assignment statements looking for group definitions:
//
//	apiV1Group:= r.Group("/api/v1")
//	sub:= group.Group("/tokens/v1")
func handleAssignment(ctx *packageMiddlewareCtx, assign *ast.AssignStmt) {
	if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
		return
	}

	lhs, ok := assign.Lhs[0].(*ast.Ident)
	if !ok {
		return
	}

	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok {
		return
	}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	if sel.Sel.Name == "Group" {
		// <ident>:= <expr>.Group("...")
		// Record the new group and its parent.
		parentIdent := identName(sel.X)
		if parentIdent != "" {
			ctx.parentGroup[lhs.Name] = parentIdent
		}
	}
}

// handleCall processes standalone call expressions (ExprStmt wrapping CallExpr).
func handleCall(ctx *packageMiddlewareCtx, call *ast.CallExpr, imports map[string]string, pkgDir string, irCalls *[]installRoutesCall) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return
	}

	methodName := sel.Sel.Name
	receiverName := identName(sel.X)

	switch methodName {
	case "Use":
		// <group>.Use(<middleware>...)
		// Check if any argument looks like a logger.
		for _, arg := range call.Args {
			if argLooksLikeLogger(arg) {
				if receiverName != "" {
					ctx.groupCoverage[receiverName] = true
				}
				return
			}
		}

	case "POST", "GET", "PUT", "DELETE", "PATCH", "Any", "Handle":
		// <group>.POST("/path", handler)
		// Register handler -> group mapping.
		if receiverName != "" && len(call.Args) >= 2 {
			for _, arg := range call.Args[1:] {
				registerHandlerArg(ctx, arg, receiverName)
			}
		}

	case "InstallRoutes":
		// <handler>.InstallRoutes(<group>)
		// Record for Pass B resolution AND mark the group as having InstallRoutes
		// calls (used for parent-child cross-package detection).
		if len(call.Args) >= 1 {
			groupArg := identName(call.Args[0])
			if groupArg != "" && receiverName != "" {
				*irCalls = append(*irCalls, installRoutesCall{
					receiverIdent: receiverName,
					groupArg:      groupArg,
				})
				ctx.installRoutesGroups[groupArg] = true
			}
		}

	default:
		// Check for aggregator calls: middleware.Install(<group>), pkg.Setup(<group>), etc.
		if aggregatorFuncNames[methodName] && len(call.Args) >= 1 {
			groupArg := identName(call.Args[0])
			if groupArg == "" {
				return
			}

			// Is the receiver a package qualifier?
			recvIdent, isIdent := sel.X.(*ast.Ident)
			if !isIdent {
				return
			}

			importPath, hasImport := imports[recvIdent.Name]
			if !hasImport {
				return
			}

			// Resolve cross-package middleware.
			if resolveExternalMiddleware(importPath, pkgDir) {
				ctx.groupCoverage[groupArg] = true
			}
		}
	}
}

// resolveInstallRoutesBody processes a single InstallRoutes call by finding the
// method body, walking it with parameter-to-argument substitution, and recording
// handler->group and group parent relationships.
func resolveInstallRoutesBody(ctx *packageMiddlewareCtx, irc installRoutesCall, methodBodies map[methodKey]*ast.FuncDecl) {
	// Find which type the receiver variable belongs to.
	// We look for any InstallRoutes method in methodBodies.
	for key, fn := range methodBodies {
		if key.methodName != "InstallRoutes" {
			continue
		}

		// Get the parameter name for the group argument.
		paramName := firstParamName(fn)
		if paramName == "" {
			continue
		}

		// Walk the method body with parameter substitution:
		// every reference to paramName maps to irc.groupArg.
		walkMethodBody(ctx, fn.Body, paramName, irc.groupArg)
	}
}

// firstParamName returns the name of the first parameter of a function declaration.
func firstParamName(fn *ast.FuncDecl) string {
	if fn.Type == nil || fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return ""
	}
	field := fn.Type.Params.List[0]
	if len(field.Names) == 0 {
		return ""
	}
	return field.Names[0].Name
}

// walkMethodBody walks a method body looking for group definitions and handler
// registrations, substituting paramName with groupArg to resolve parameter-dependent
// identifiers.
func walkMethodBody(ctx *packageMiddlewareCtx, body *ast.BlockStmt, paramName, groupArg string) {
	// localSubst maps local variable names to their resolved group idents.
	// The method parameter maps to the passed group argument.
	localSubst := map[string]string{
		paramName: groupArg,
	}

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			if len(node.Lhs) == 1 && len(node.Rhs) == 1 {
				lhs, ok := node.Lhs[0].(*ast.Ident)
				if !ok {
					break
				}
				call, ok := node.Rhs[0].(*ast.CallExpr)
				if !ok {
					break
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					break
				}
				if sel.Sel.Name == "Group" {
					parentLocal := identName(sel.X)
					resolvedParent := localSubst[parentLocal]
					if resolvedParent == "" {
						resolvedParent = parentLocal
					}
					// Create a unique name for the sub-group.
					subGroupName := "__sub:" + lhs.Name + ":" + groupArg
					ctx.parentGroup[subGroupName] = resolvedParent
					localSubst[lhs.Name] = subGroupName
				}
			}

		case *ast.ExprStmt:
			call, ok := node.X.(*ast.CallExpr)
			if !ok {
				break
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				break
			}
			methodName := sel.Sel.Name
			receiverLocal := identName(sel.X)
			resolvedReceiver := localSubst[receiverLocal]
			if resolvedReceiver == "" {
				resolvedReceiver = receiverLocal
			}

			switch methodName {
			case "POST", "GET", "PUT", "DELETE", "PATCH", "Any", "Handle":
				if len(call.Args) >= 2 {
					for _, arg := range call.Args[1:] {
						registerHandlerArg(ctx, arg, resolvedReceiver)
					}
				}
			case "Use":
				for _, arg := range call.Args {
					if argLooksLikeLogger(arg) {
						ctx.groupCoverage[resolvedReceiver] = true
						return false
					}
				}
			}
		}
		return true
	})
}

// registerHandlerArg extracts handler function names from route registration arguments.
func registerHandlerArg(ctx *packageMiddlewareCtx, arg ast.Expr, groupIdent string) {
	switch a := arg.(type) {
	case *ast.SelectorExpr:
		// h.CreateToken -> register "CreateToken" on groupIdent
		ctx.handlerGroups[a.Sel.Name] = groupIdent
	case *ast.Ident:
		// plainHandler -> register "plainHandler" on groupIdent
		ctx.handlerGroups[a.Name] = groupIdent
	case *ast.CallExpr:
		// wrapper(h.CreateToken) -> try to extract inner arg
		for _, innerArg := range a.Args {
			registerHandlerArg(ctx, innerArg, groupIdent)
		}
	}
}

// identName extracts the identifier name from an expression.
// Returns "" for non-identifier expressions.
func identName(expr ast.Expr) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// resolveExternalMiddleware determines whether an imported package installs
// logging middleware.
//
// For in-project imports (within the same Go module): walks into the package
// directory and checks if the Install/Setup function body calls Use() with
// logger-shaped args.
//
// For external imports: uses the trusted package segment heuristic.
func resolveExternalMiddleware(importPath, pkgDir string) bool {
	// Try to find go.mod to determine module path.
	modulePath, moduleDir := findGoModule(pkgDir)

	if modulePath != "" && strings.HasPrefix(importPath, modulePath) {
		// In-project import: resolve to directory on disk.
		relPath := strings.TrimPrefix(importPath, modulePath)
		relPath = strings.TrimPrefix(relPath, "/")
		pkgOnDisk := filepath.Join(moduleDir, relPath)

		return resolveInProjectMiddleware(pkgOnDisk)
	}

	// External package: apply heuristic trust.
	return isTrustedMiddlewarePackage(importPath)
}

// findGoModule walks up from startDir looking for go.mod and returns
// (modulePath, moduleDir). Returns ("", "") if not found.
func findGoModule(startDir string) (string, string) {
	dir := startDir
	for {
		gomodPath := filepath.Join(dir, "go.mod")
		data, err := os.ReadFile(gomodPath)
		if err == nil {
			// Extract module path from first line: "module github.com/foo/bar"
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "module ") {
					modPath := strings.TrimPrefix(line, "module ")
					modPath = strings.TrimSpace(modPath)
					return modPath, dir
				}
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root
		}
		dir = parent
	}
	return "", ""
}

// resolveInProjectMiddleware parses a package directory and checks if any
// aggregator function (Install, Setup, etc.) calls Use() with logger-shaped args.
func resolveInProjectMiddleware(pkgDirOnDisk string) bool {
	// Validate resolved path doesn't escape project root.
	cleanPath := filepath.Clean(pkgDirOnDisk)
	if strings.Contains(cleanPath, "..") {
		return false
	}

	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, cleanPath)
	if len(pkgFiles) == 0 {
		return false
	}

	for _, file := range pkgFiles {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if !aggregatorFuncNames[fn.Name.Name] {
				continue
			}
			// Check if the function body calls Use() with logger-shaped args.
			if blockHasLoggerArg(fn.Body) {
				return true
			}
		}
	}
	return false
}

// isTrustedMiddlewarePackage checks if any segment of the import path
// matches a trusted middleware package name (heuristic).
func isTrustedMiddlewarePackage(importPath string) bool {
	segments := strings.Split(strings.ToLower(importPath), "/")
	for _, seg := range segments {
		for _, trusted := range trustedPackageSegments {
			if seg == trusted {
				return true
			}
		}
	}
	return false
}
