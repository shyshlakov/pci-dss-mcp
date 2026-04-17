package authscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type signatureMiddlewareCtx struct {
	groupCoverage       map[string]bool
	handlerGroups       map[string]string
	parentGroup         map[string]string
	installRoutesGroups map[string]bool
}

var (
	webhookCacheMu       sync.Mutex
	webhookCachePackages = map[string]*signatureMiddlewareCtx{}
)

func ResetWebhookMiddlewareCache() {
	webhookCacheMu.Lock()
	webhookCachePackages = map[string]*signatureMiddlewareCtx{}
	webhookCacheMu.Unlock()
}

var trustedSignaturePackageSegments = []string{
	"middleware", "webhook", "signature", "hmac", "verify", "auth", "security",
}

const webhookMaxParentWalk = 5

var signatureMiddlewareNameRE = regexp.MustCompile(`(?i)(hmac|signature|webhook|verify|auth)`)

var signatureAggregatorFuncNames = map[string]bool{
	"Install":   true,
	"Setup":     true,
	"Register":  true,
	"Configure": true,
	"Apply":     true,
}

func argLooksLikeSignatureMiddleware(arg ast.Expr) bool {
	switch a := arg.(type) {
	case *ast.Ident:
		return signatureMiddlewareNameRE.MatchString(a.Name)
	case *ast.SelectorExpr:
		if signatureMiddlewareNameRE.MatchString(a.Sel.Name) {
			return true
		}
		if recv, ok := a.X.(*ast.Ident); ok && signatureMiddlewareNameRE.MatchString(recv.Name) {
			return true
		}
		return false
	case *ast.CallExpr:
		if sel, ok := a.Fun.(*ast.SelectorExpr); ok {
			if signatureMiddlewareNameRE.MatchString(sel.Sel.Name) {
				return true
			}
			if recv, ok := sel.X.(*ast.Ident); ok && signatureMiddlewareNameRE.MatchString(recv.Name) {
				return true
			}
			return false
		}
		if ident, ok := a.Fun.(*ast.Ident); ok {
			return signatureMiddlewareNameRE.MatchString(ident.Name)
		}
	}
	return false
}

func HasSignatureMiddlewareCoverage(targetPath, handlerFuncName string) bool {
	pkgDir := filepath.Dir(targetPath)

	ctx := getOrBuildSignatureCtx(pkgDir)
	if ctx != nil {
		if groupIdent, ok := ctx.handlerGroups[handlerFuncName]; ok {
			if signatureGroupHasCoverage(ctx, groupIdent) {
				return true
			}
		}
		if ctx.handlerGroups[handlerFuncName] == wrapperMarker {
			return true
		}
	}

	childPkg := pkgDir
	current := pkgDir
	for i := 0; i < webhookMaxParentWalk; i++ {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		parentCtx := getOrBuildSignatureCtx(parent)
		if parentCtx != nil && signatureParentHasMiddlewareCoveringChild(parentCtx, childPkg) {
			return true
		}
		current = parent
	}

	return false
}

const wrapperMarker = "__wrapped:signature"

func getOrBuildSignatureCtx(pkgDir string) *signatureMiddlewareCtx {
	webhookCacheMu.Lock()
	ctx, cached := webhookCachePackages[pkgDir]
	webhookCacheMu.Unlock()

	if !cached {
		ctx = buildSignatureMiddlewareCtx(pkgDir)
		webhookCacheMu.Lock()
		webhookCachePackages[pkgDir] = ctx
		webhookCacheMu.Unlock()
	}
	return ctx
}

func signatureParentHasMiddlewareCoveringChild(ctx *signatureMiddlewareCtx, childPkgDir string) bool {
	for groupIdent, covered := range ctx.groupCoverage {
		if !covered {
			continue
		}
		if ctx.installRoutesGroups[groupIdent] {
			return true
		}
		for irGroup := range ctx.installRoutesGroups {
			if signatureIsAncestorGroup(ctx, irGroup, groupIdent) {
				return true
			}
		}
	}
	return false
}

func signatureIsAncestorGroup(ctx *signatureMiddlewareCtx, childIdent, ancestorIdent string) bool {
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

func signatureGroupHasCoverage(ctx *signatureMiddlewareCtx, groupIdent string) bool {
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

func buildSignatureMiddlewareCtx(pkgDir string) *signatureMiddlewareCtx {
	fset := token.NewFileSet()
	pkgFiles := parseSignaturePkgFiles(fset, pkgDir)
	if len(pkgFiles) == 0 {
		return nil
	}

	ctx := &signatureMiddlewareCtx{
		groupCoverage:       make(map[string]bool),
		handlerGroups:       make(map[string]string),
		parentGroup:         make(map[string]string),
		installRoutesGroups: make(map[string]bool),
	}

	type fileInfo struct {
		file    *ast.File
		imports map[string]string
	}
	var allFiles []fileInfo

	for _, file := range pkgFiles {
		imports := make(map[string]string)
		for _, imp := range file.Imports {
			if imp.Path == nil {
				continue
			}
			importPath := strings.Trim(imp.Path.Value, `"`)
			alias := filepath.Base(importPath)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			imports[alias] = importPath
		}
		allFiles = append(allFiles, fileInfo{file: file, imports: imports})
	}

	for _, fi := range allFiles {
		passASignature(ctx, fi.file, fi.imports, pkgDir)
	}

	return ctx
}

func parseSignaturePkgFiles(fset *token.FileSet, dir string) []*ast.File {
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

func passASignature(ctx *signatureMiddlewareCtx, file *ast.File, imports map[string]string, pkgDir string) {
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			handleAssignmentSignature(ctx, node)
		case *ast.ExprStmt:
			if call, ok := node.X.(*ast.CallExpr); ok {
				handleCallSignature(ctx, call, imports, pkgDir)
			}
		}
		return true
	})
}

func handleAssignmentSignature(ctx *signatureMiddlewareCtx, assign *ast.AssignStmt) {
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
		parentIdent := signatureIdentName(sel.X)
		if parentIdent != "" {
			ctx.parentGroup[lhs.Name] = parentIdent
		}
	}
}

func handleCallSignature(ctx *signatureMiddlewareCtx, call *ast.CallExpr, imports map[string]string, pkgDir string) {
	sel, isSel := call.Fun.(*ast.SelectorExpr)
	if !isSel {
		return
	}

	methodName := sel.Sel.Name
	receiverName := signatureIdentName(sel.X)

	switch methodName {
	case "Use":
		for _, arg := range call.Args {
			if argLooksLikeSignatureMiddleware(arg) {
				if receiverName != "" {
					ctx.groupCoverage[receiverName] = true
				}
				return
			}
		}

	case "POST", "GET", "PUT", "DELETE", "PATCH", "Any", "Handle", "HandleFunc":
		if len(call.Args) >= 2 {
			for _, arg := range call.Args[1:] {
				signatureRegisterHandlerArg(ctx, arg, receiverName)
			}
		}

	case "InstallRoutes":
		if len(call.Args) >= 1 {
			groupArg := signatureIdentName(call.Args[0])
			if groupArg != "" && receiverName != "" {
				ctx.installRoutesGroups[groupArg] = true
			}
		}

	default:
		if signatureAggregatorFuncNames[methodName] && len(call.Args) >= 1 {
			groupArg := signatureIdentName(call.Args[0])
			if groupArg == "" {
				return
			}
			recvIdent, isIdent := sel.X.(*ast.Ident)
			if !isIdent {
				return
			}
			importPath, hasImport := imports[recvIdent.Name]
			if !hasImport {
				return
			}
			if signatureResolveExternalMiddleware(importPath, pkgDir) {
				ctx.groupCoverage[groupArg] = true
			}
		}
	}
}

func signatureRegisterHandlerArg(ctx *signatureMiddlewareCtx, arg ast.Expr, groupIdent string) {
	switch a := arg.(type) {
	case *ast.SelectorExpr:
		ctx.handlerGroups[a.Sel.Name] = groupIdent
	case *ast.Ident:
		ctx.handlerGroups[a.Name] = groupIdent
	case *ast.CallExpr:
		if fnIdent, ok := a.Fun.(*ast.Ident); ok && signatureMiddlewareNameRE.MatchString(fnIdent.Name) {
			for _, innerArg := range a.Args {
				inner := signatureInnerHandlerName(innerArg)
				if inner != "" {
					ctx.handlerGroups[inner] = wrapperMarker
				}
			}
			return
		}
		if fnSel, ok := a.Fun.(*ast.SelectorExpr); ok && signatureMiddlewareNameRE.MatchString(fnSel.Sel.Name) {
			for _, innerArg := range a.Args {
				inner := signatureInnerHandlerName(innerArg)
				if inner != "" {
					ctx.handlerGroups[inner] = wrapperMarker
				}
			}
			return
		}
		for _, innerArg := range a.Args {
			signatureRegisterHandlerArg(ctx, innerArg, groupIdent)
		}
	}
}

func signatureInnerHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}

func signatureIdentName(expr ast.Expr) string {
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func signatureResolveExternalMiddleware(importPath, pkgDir string) bool {
	modulePath, moduleDir := signatureFindGoModule(pkgDir)

	if modulePath != "" && strings.HasPrefix(importPath, modulePath) {
		relPath := strings.TrimPrefix(importPath, modulePath)
		relPath = strings.TrimPrefix(relPath, "/")
		pkgOnDisk := filepath.Join(moduleDir, relPath)
		return signatureResolveInProjectMiddleware(pkgOnDisk)
	}

	return signatureIsTrustedMiddlewarePackage(importPath)
}

func signatureFindGoModule(startDir string) (string, string) {
	dir := startDir
	for {
		gomodPath := filepath.Join(dir, "go.mod")
		data, err := os.ReadFile(gomodPath)
		if err == nil {
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
			break
		}
		dir = parent
	}
	return "", ""
}

func signatureResolveInProjectMiddleware(pkgDirOnDisk string) bool {
	cleanPath := filepath.Clean(pkgDirOnDisk)
	if strings.Contains(cleanPath, "..") {
		return false
	}

	fset := token.NewFileSet()
	pkgFiles := parseSignaturePkgFiles(fset, cleanPath)
	if len(pkgFiles) == 0 {
		return false
	}

	for _, file := range pkgFiles {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if !signatureAggregatorFuncNames[fn.Name.Name] {
				continue
			}
			if signatureBlockHasArg(fn.Body) {
				return true
			}
		}
	}
	return false
}

func signatureIsTrustedMiddlewarePackage(importPath string) bool {
	segments := strings.Split(strings.ToLower(importPath), "/")
	for _, seg := range segments {
		for _, trusted := range trustedSignaturePackageSegments {
			if seg == trusted {
				return true
			}
		}
	}
	return false
}

func signatureBlockHasArg(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			if argLooksLikeSignatureMiddleware(arg) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
