package auditscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
	"sync"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// ---------- Logger API field method sets ----------

// slogFieldMethods are slog package-level functions that take (key, value)
// where the first arg is the field name string.
var slogFieldMethods = map[string]bool{
	"String":   true,
	"Int":      true,
	"Int64":    true,
	"Uint64":   true,
	"Float64":  true,
	"Bool":     true,
	"Time":     true,
	"Duration": true,
	"Any":      true,
	"Group":    true,
}

// zapFieldMethods are zap package-level functions that take (key, value).
// zap.Error(err) is special — implicit field name "error".
var zapFieldMethods = map[string]bool{
	"String":     true,
	"Int":        true,
	"Int64":      true,
	"Int32":      true,
	"Int16":      true,
	"Int8":       true,
	"Uint":       true,
	"Uint64":     true,
	"Uint32":     true,
	"Uint16":     true,
	"Uint8":      true,
	"Float64":    true,
	"Float32":    true,
	"Bool":       true,
	"Time":       true,
	"Duration":   true,
	"Binary":     true,
	"ByteString": true,
	"Any":        true,
	"NamedError": true,
	"Reflect":    true,
	"Stringer":   true,
}

// zapImplicitErrorMethods produce an implicit "error" field name.
var zapImplicitErrorMethods = map[string]bool{
	"Error": true,
}

// zerologFieldMethods are zerolog chain methods that take (key, value).
// zerolog.Err(err) is special — implicit field name "error".
var zerologFieldMethods = map[string]bool{
	"Str":       true,
	"Strs":      true,
	"Int":       true,
	"Int8":      true,
	"Int16":     true,
	"Int32":     true,
	"Int64":     true,
	"Uint":      true,
	"Uint8":     true,
	"Uint16":    true,
	"Uint32":    true,
	"Uint64":    true,
	"Float32":   true,
	"Float64":   true,
	"Bool":      true,
	"Time":      true,
	"Dur":       true,
	"Bytes":     true,
	"RawJSON":   true,
	"Any":       true,
	"Interface": true,
}

// zerologImplicitErrorMethods produce an implicit "error" field name.
var zerologImplicitErrorMethods = map[string]bool{
	"Err": true,
}

// ---------- Import path sets for logger detection ----------

// slogImportPaths identifies slog imports.
var slogImportPaths = map[string]bool{
	"log/slog": true,
}

// zapImportPaths identifies zap imports.
var zapImportPaths = map[string]bool{
	"go.uber.org/zap": true,
}

// zerologImportPaths identifies zerolog imports.
var zerologImportPaths = map[string]bool{
	"github.com/rs/zerolog":     true,
	"github.com/rs/zerolog/log": true,
}

// logrusImportPaths identifies logrus imports.
var logrusImportPaths = map[string]bool{
	"github.com/sirupsen/logrus": true,
}

// ---------- Public API ----------

// ExtractLogFields parses all.go files in pkgDir, finds the function named
// funcName, extracts structured log field names from its body (and 1 level of
// local helper calls), and returns the deduplicated list of field name strings.
//
// fileImports maps import alias -> import path for the file containing the
// function call that references this middleware. Used for cross-package constant
// resolution (e.g., logger.LogKeyRequestID -> "request_id").
//
// Returns nil if pkgDir cannot be parsed or funcName is not found (graceful
// degradation).
func ExtractLogFields(pkgDir string, funcName string, fileImports map[string]string) []string {
	// Validate pkgDir — reject paths containing ".".
	cleanDir := filepath.Clean(pkgDir)
	if strings.Contains(cleanDir, "..") {
		return nil
	}

	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, cleanDir)
	if len(pkgFiles) == 0 {
		return nil
	}

	// Collect all methods across the package for method-value resolution.
	// Key: method name, Value: FuncDecl (methods may exist on any receiver type).
	pkgMethods := map[string]*ast.FuncDecl{}
	// Also collect per-file data for the target function search.
	type fileEntry struct {
		file    *ast.File
		aliases map[string]string
	}
	var files []fileEntry

	for _, file := range pkgFiles {
		aliases := buildImportAliases(file)
		for alias, importPath := range fileImports {
			if _, exists := aliases[alias]; !exists {
				aliases[alias] = importPath
			}
		}
		files = append(files, fileEntry{file: file, aliases: aliases})

		// Index all methods (with receiver) for method-value resolution.
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Recv == nil || fn.Body == nil {
				continue
			}
			pkgMethods[fn.Name.Name] = fn
		}
	}

	for _, fe := range files {
		localFuncs := sameFileFuncs(fe.file)

		for _, decl := range fe.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if fn.Name.Name != funcName {
				continue
			}

			constResolver := buildConstResolver(cleanDir, fe.aliases)

			// Extract fields from the target function body.
			fields := extractFieldsFromBody(fn.Body, fe.aliases, localFuncs, constResolver, false)

			// Also follow method values passed as arguments (e.g. r.Use(m.requestLogger)).
			// to r.Use() instead of calling them inline.
			methodValueFields := extractFieldsFromMethodValues(fn, pkgMethods, fe.aliases, constResolver)
			fields = append(fields, methodValueFields...)

			return dedup(fields)
		}
	}

	return nil
}

// extractFieldsFromMethodValues finds method values (m.methodName) used as
// arguments in function calls within the target function body, resolves them
// to method declarations in the same package, and extracts log fields from
// those method bodies.
//
// This handles the common pattern:
//
//	func (m *Middleware) Install(r gin.IRouter) {
//	 r.Use(m.requestLogger, m.audit.AuditLogger)
//	}
//
// where requestLogger is a method on *Middleware containing logrus.Fields.
func extractFieldsFromMethodValues(targetFn *ast.FuncDecl, pkgMethods map[string]*ast.FuncDecl, aliases map[string]string, constResolver func(string, string) string) []string {
	if targetFn.Body == nil {
		return nil
	}

	// Determine the receiver parameter name (e.g. "m" from "func (m *Middleware) Install(...)").
	receiverName := ""
	if targetFn.Recv != nil && len(targetFn.Recv.List) > 0 {
		if names := targetFn.Recv.List[0].Names; len(names) > 0 {
			receiverName = names[0].Name
		}
	}

	var fields []string
	seen := map[string]bool{}

	ast.Inspect(targetFn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		methodName := sel.Sel.Name

		// Case 1: m.requestLogger — receiver method value.
		if ident, ok := sel.X.(*ast.Ident); ok && receiverName != "" && ident.Name == receiverName {
			if !seen[methodName] {
				seen[methodName] = true
				if method, exists := pkgMethods[methodName]; exists {
					mf := extractFieldsFromBody(method.Body, aliases, nil, constResolver, true)
					fields = append(fields, mf...)
				}
			}
		}

		// Case 2: m.audit.AuditLogger — nested selector on receiver field.
		// We can't resolve this without type info, but we can try: if the inner selector
		// matches the receiver, the outer selector might be a method on a field's type.
		// For now, skip — this would need go/types for proper resolution.

		return true
	})

	return fields
}

// ---------- Internal functions ----------

// extractFieldsFromBody walks the given function body AST and extracts
// structured log field names from all 4 supported logger APIs:
// logrus, slog, zap, zerolog.
//
// constResolver is called for cross-package constant resolution (pkgAlias, constName) -> string.
// If inHelper is true, this is a recursive call for a local helper function (no deeper recursion).
func extractFieldsFromBody(body *ast.BlockStmt, fileImports map[string]string, localFuncs map[string]*ast.FuncDecl, constResolver func(pkgAlias, constName string) string, inHelper bool) []string {
	if body == nil {
		return nil
	}

	// Build reverse lookup: alias -> logger type.
	aliasToLogger := classifyAliases(fileImports)

	var fields []string
	// Track local function calls for 1-level following.
	var localCalls []string
	// Track already-processed CallExpr nodes to avoid double-counting in chains.
	// When extractFieldsFromCallExpr recursively processes inner chain calls,
	// we mark them so the outer ast.Inspect walk skips them.
	visited := make(map[*ast.CallExpr]bool)

	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if !visited[node] {
				extracted := extractFieldsFromCallChain(node, aliasToLogger, constResolver, visited)
				fields = append(fields, extracted...)
			}

			// Collect local function calls for helper following.
			if ident, ok := node.Fun.(*ast.Ident); ok {
				localCalls = append(localCalls, ident.Name)
			}

		case *ast.CompositeLit:
			extracted := extractFieldsFromCompositeLit(node, constResolver)
			fields = append(fields, extracted...)

		case *ast.AssignStmt:
			if field := extractFieldsFromMapIndexAssign(node, constResolver); field != "" {
				fields = append(fields, field)
			}
		}
		return true
	})

	// Follow local helper calls — 1 level only (no recursion into helpers).
	if !inHelper && localFuncs != nil {
		seen := make(map[string]bool)
		for _, name := range localCalls {
			if seen[name] {
				continue
			}
			seen[name] = true
			if helperFn, ok := localFuncs[name]; ok && helperFn.Body != nil {
				helperFields := extractFieldsFromBody(helperFn.Body, fileImports, nil, constResolver, true)
				fields = append(fields, helperFields...)
			}
		}
	}

	return fields
}

// extractFieldsFromCallChain extracts field names from a logger API call expression,
// recursively following zerolog-style chains. It marks all processed CallExpr nodes
// in visited so the outer ast.Inspect walk does not double-count them.
//
// Handles:
// - slog.String("key", val), slog.Int("key", val), etc.
// - zap.String("key", val), zap.Error(err) -> "error"
// - zerolog chain:.Str("key", val),.Err(err) -> "error"
// - logrus entry.WithField("key", val)
func extractFieldsFromCallChain(call *ast.CallExpr, aliasToLogger map[string]string, constResolver func(pkgAlias, constName string) string, visited map[*ast.CallExpr]bool) []string {
	visited[call] = true

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}

	methodName := sel.Sel.Name

	switch x := sel.X.(type) {
	case *ast.Ident:
		return extractIdentCallFields(x, methodName, call.Args, aliasToLogger)
	case *ast.CallExpr:
		return extractChainedCallFields(x, methodName, call.Args, aliasToLogger, constResolver, visited)
	case *ast.SelectorExpr:
		return extractZerologMethodFields(methodName, call.Args)
	}

	return nil
}

// extractIdentCallFields handles the `pkg.Method(...)` / `entry.WithField(...)`
// shape where the selector's X is a plain identifier. Dispatches per logger
// family (slog, zap, zerolog) or falls through to the generic logrus
// WithField idiom.
func extractIdentCallFields(x *ast.Ident, methodName string, args []ast.Expr, aliasToLogger map[string]string) []string {
	loggerType, isLogger := aliasToLogger[x.Name]
	if !isLogger {
		return withFieldLiteral(methodName, args)
	}
	switch loggerType {
	case "slog":
		return firstStringLiteralArg(slogFieldMethods, methodName, args)
	case "zap":
		if fields := firstStringLiteralArg(zapFieldMethods, methodName, args); fields != nil {
			return fields
		}
		if zapImplicitErrorMethods[methodName] {
			return []string{"error"}
		}
	case "zerolog":
		if fields := firstStringLiteralArg(zerologFieldMethods, methodName, args); fields != nil {
			return fields
		}
		if zerologImplicitErrorMethods[methodName] {
			return []string{"error"}
		}
	}
	return nil
}

// extractChainedCallFields handles `.Str("k", v).Int("k2", v2).Msg("done")`
// style zerolog chains and logrus WithField chains, recursing into the inner
// CallExpr to harvest remaining fields.
func extractChainedCallFields(inner *ast.CallExpr, methodName string, args []ast.Expr, aliasToLogger map[string]string, constResolver func(pkgAlias, constName string) string, visited map[*ast.CallExpr]bool) []string {
	var fields []string
	fields = append(fields, firstStringLiteralArg(zerologFieldMethods, methodName, args)...)
	if zerologImplicitErrorMethods[methodName] {
		fields = append(fields, "error")
	}
	fields = append(fields, withFieldLiteral(methodName, args)...)
	fields = append(fields, extractFieldsFromCallChain(inner, aliasToLogger, constResolver, visited)...)
	return fields
}

// extractZerologMethodFields handles `log.Info().Str("k", v)` where the inner
// selector is itself a SelectorExpr (the `log.Info` part).
func extractZerologMethodFields(methodName string, args []ast.Expr) []string {
	if fields := firstStringLiteralArg(zerologFieldMethods, methodName, args); fields != nil {
		return fields
	}
	if zerologImplicitErrorMethods[methodName] {
		return []string{"error"}
	}
	return nil
}

// firstStringLiteralArg returns []{field} when methodName is in methodSet and
// the first argument is a string literal. Returns nil otherwise.
func firstStringLiteralArg(methodSet map[string]bool, methodName string, args []ast.Expr) []string {
	if !methodSet[methodName] || len(args) < 1 {
		return nil
	}
	field := extractStringLiteral(args[0])
	if field == "" {
		return nil
	}
	return []string{field}
}

// withFieldLiteral handles the logrus `entry.WithField("key", val)` idiom.
func withFieldLiteral(methodName string, args []ast.Expr) []string {
	if methodName != "WithField" || len(args) < 1 {
		return nil
	}
	field := extractStringLiteral(args[0])
	if field == "" {
		return nil
	}
	return []string{field}
}

// extractFieldsFromCompositeLit extracts field names from composite literals:
// - logrus.Fields{"key": val,...} -> extract keys
// - slog.Attr{Key: "key", Value:...} -> extract Key value
// - Elided-type composite literals inside []slog.Attr{} slices (Type == nil)
func extractFieldsFromCompositeLit(lit *ast.CompositeLit, constResolver func(pkgAlias, constName string) string) []string {
	var fields []string

	typeName := resolveCompositeLitTypeName(lit)

	switch typeName {
	case "Fields":
		// logrus.Fields{"key1": val1, "key2": val2}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			field := resolveKeyExpr(kv.Key, constResolver)
			if field != "" {
				fields = append(fields, field)
			}
		}

	case "Attr":
		// slog.Attr{Key: "event", Value: slog.StringValue("login")}
		fields = append(fields, extractAttrKeyField(lit)...)

	case "":
		// Type-elided composite literal — may be inside []slog.Attr{...}.
		// Check if it has Key/Value fields matching slog.Attr structure.
		if looksLikeAttrLiteral(lit) {
			fields = append(fields, extractAttrKeyField(lit)...)
		}
	}

	return fields
}

// resolveCompositeLitTypeName returns the selector name of a composite literal's type.
// For logrus.Fields{...} returns "Fields", for slog.Attr{...} returns "Attr".
// Returns "" if type is nil or not a selector expression.
func resolveCompositeLitTypeName(lit *ast.CompositeLit) string {
	if lit.Type == nil {
		return ""
	}
	sel, ok := lit.Type.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return sel.Sel.Name
}

// extractAttrKeyField extracts the "Key" field value from a slog.Attr-like
// composite literal: {Key: "event", Value:...}
func extractAttrKeyField(lit *ast.CompositeLit) []string {
	var fields []string
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*ast.Ident)
		if !ok || keyIdent.Name != "Key" {
			continue
		}
		if field := extractStringLiteral(kv.Value); field != "" {
			fields = append(fields, field)
		}
	}
	return fields
}

// looksLikeAttrLiteral checks if a type-elided composite literal looks like
// slog.Attr by checking for Key and Value fields (KeyValueExpr with "Key" ident).
func looksLikeAttrLiteral(lit *ast.CompositeLit) bool {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		keyIdent, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if keyIdent.Name == "Key" || keyIdent.Name == "Value" {
			return true
		}
	}
	return false
}

// extractFieldsFromMapIndexAssign extracts a field name from map index
// assignment statements: fields["key"] = val or fields[pkg.Const] = val.
func extractFieldsFromMapIndexAssign(stmt *ast.AssignStmt, constResolver func(pkgAlias, constName string) string) string {
	if len(stmt.Lhs) == 0 {
		return ""
	}

	indexExpr, ok := stmt.Lhs[0].(*ast.IndexExpr)
	if !ok {
		return ""
	}

	return resolveKeyExpr(indexExpr.Index, constResolver)
}

// resolveConstantInPackage parses all.go files in pkgDir and looks for a
// top-level const declaration with the given name. Returns the string literal
// value, or "" if not found.
//
// Validates pkgDir with filepath.Clean and rejects paths containing ".".
func resolveConstantInPackage(pkgDir string, constName string) string {
	cleanDir := filepath.Clean(pkgDir)
	if strings.Contains(cleanDir, "..") {
		return ""
	}

	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, cleanDir)

	for _, file := range pkgFiles {
		if val := resolveConstant(file, constName); val != "" {
			return val
		}
	}
	return ""
}

// resolveConstant finds a top-level constant declaration with the given name
// and returns its string value, or "" if not found.
//
// Duplicated from sqlscanner/gormparse.go to avoid cross-scanner dependency.
// The function is <25 lines and unlikely to diverge.
func resolveConstant(file *ast.File, name string) string {
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name {
					continue
				}
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
						return strings.Trim(lit.Value, `"`+"`")
					}
				}
			}
		}
	}
	return ""
}

// ---------- Helper functions ----------

// buildImportAliases builds a map from import alias to import path for a file.
func buildImportAliases(file *ast.File) map[string]string {
	aliases := make(map[string]string)
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			alias = imp.Name.Name
		} else {
			// Use last segment of import path as default alias.
			alias = filepath.Base(importPath)
		}
		aliases[alias] = importPath
	}
	return aliases
}

// classifyAliases maps each import alias to its logger type string
// (slog, zap, zerolog, logrus) based on the import path.
func classifyAliases(fileImports map[string]string) map[string]string {
	result := make(map[string]string)
	for alias, importPath := range fileImports {
		switch {
		case slogImportPaths[importPath]:
			result[alias] = "slog"
		case zapImportPaths[importPath]:
			result[alias] = "zap"
		case zerologImportPaths[importPath]:
			result[alias] = "zerolog"
		case logrusImportPaths[importPath]:
			result[alias] = "logrus"
		}
	}
	return result
}

// buildConstResolver creates a constant resolver function that uses findGoModule
// and parser.ParseDir to resolve cross-package constants.
func buildConstResolver(pkgDir string, aliases map[string]string) func(pkgAlias, constName string) string {
	return func(pkgAlias, constName string) string {
		if pkgAlias == "" {
			// Local constant — resolve within current package.
			return resolveConstantInPackage(pkgDir, constName)
		}

		// Cross-package constant: look up import path from alias.
		importPath, ok := aliases[pkgAlias]
		if !ok {
			return ""
		}

		// Resolve import path to on-disk directory using findGoModule.
		modulePath, moduleDir := findGoModule(pkgDir)
		if modulePath == "" {
			return ""
		}

		if !strings.HasPrefix(importPath, modulePath) {
			// External dependency — cannot resolve on disk.
			return ""
		}

		relPath := strings.TrimPrefix(importPath, modulePath)
		relPath = strings.TrimPrefix(relPath, "/")
		constPkgDir := filepath.Join(moduleDir, relPath)

		// Validate resolved path.
		cleanPath := filepath.Clean(constPkgDir)
		if strings.Contains(cleanPath, "..") {
			return ""
		}

		return resolveConstantInPackage(cleanPath, constName)
	}
}

// extractStringLiteral extracts a string value from an AST expression.
// Returns "" if the expression is not a string literal.
func extractStringLiteral(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	return strings.Trim(lit.Value, `"`+"`")
}

// resolveKeyExpr resolves a map key expression to a string field name.
// Handles: string literals, local identifiers (constants), and selector
// expressions (cross-package constants like logger.LogKeyFoo).
func resolveKeyExpr(expr ast.Expr, constResolver func(pkgAlias, constName string) string) string {
	switch key := expr.(type) {
	case *ast.BasicLit:
		if key.Kind == token.STRING {
			return strings.Trim(key.Value, `"`+"`")
		}
	case *ast.Ident:
		// Local constant reference.
		if constResolver != nil {
			if resolved := constResolver("", key.Name); resolved != "" {
				return resolved
			}
		}
		// Fall back to the identifier name itself (may be useful for fuzzy matching).
		return key.Name
	case *ast.SelectorExpr:
		// Cross-package constant: pkgAlias.ConstName
		if x, ok := key.X.(*ast.Ident); ok && constResolver != nil {
			if resolved := constResolver(x.Name, key.Sel.Name); resolved != "" {
				return resolved
			}
		}
	}
	return ""
}

// dedup returns a deduplicated copy of the string slice, preserving order.
func dedup(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(ss))
	result := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ---------- PCI DSS 10.2.1 Field Matching ----------

// PCIDSSFieldCategory represents one of the 5 required audit log field categories.
type PCIDSSFieldCategory struct {
	Name    string   // e.g., "user_identification"
	Aliases []string // fuzzy match aliases (pre-normalized)
}

// FieldCoverageResult holds the scoring result.
type FieldCoverageResult struct {
	Score             int                 // 0-5 matched categories
	Total             int                 // always 5
	MatchedCategories map[string][]string // category -> matched field names
	MissingCategories []string            // category names with no match
	TimestampAuto     bool                // true if auto-injected by logger framework
}

// pciDSSFieldCategories defines the 5 required PCI DSS 10.2.1 field categories.
var pciDSSFieldCategories = []PCIDSSFieldCategory{
	{Name: "user_identification", Aliases: []string{"userid", "uid", "subject", "principal", "actor", "username", "accountid", "callerid", "operatorid"}},
	{Name: "timestamp", Aliases: []string{"timestamp", "time", "ts", "createdat", "datetime", "date"}},
	{Name: "event_type", Aliases: []string{"action", "event", "eventtype", "operation", "method", "httpmethod", "url", "path", "endpoint", "requesttype"}},
	{Name: "outcome", Aliases: []string{"outcome", "result", "status", "httpstatus", "success", "error", "responsecode", "statuscode"}},
	{Name: "affected_resource", Aliases: []string{"resource", "target", "object", "affected", "entity", "record", "item", "path", "endpoint", "table", "collection"}},
}

// autoTimestampImportPaths lists import paths for loggers that auto-inject timestamp.
// slog is explicitly NOT included — it does NOT auto-inject timestamps.
var autoTimestampImportPaths = map[string]bool{
	"github.com/sirupsen/logrus": true,
	"go.uber.org/zap":            true,
	"github.com/rs/zerolog":      true,
	"github.com/rs/zerolog/log":  true,
}

// normalize strips underscores, hyphens, dots and lowercases a field name.
func normalize(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("_", "", "-", "", ".", "").Replace(s)
	return s
}

// matchesCategory checks if a normalized field name matches any alias in the category.
func matchesCategory(fieldName string, aliases []string) bool {
	norm := normalize(fieldName)
	for _, alias := range aliases {
		if strings.Contains(norm, alias) {
			return true
		}
	}
	return false
}

// MatchPCIDSSFields matches extracted field names against the 5 PCI DSS 10.2.1 categories (,, ).
func MatchPCIDSSFields(fields []string, fileImports map[string]string) *FieldCoverageResult {
	result := &FieldCoverageResult{
		Total:             5,
		MatchedCategories: make(map[string][]string),
	}

	// Check timestamp auto-detection from logger imports.
	for _, importPath := range fileImports {
		if autoTimestampImportPaths[importPath] {
			result.TimestampAuto = true
			break
		}
	}

	// If timestamp is auto-covered, seed the matched categories.
	if result.TimestampAuto {
		// Determine which logger for the label.
		autoLabel := "auto"
		for alias, importPath := range fileImports {
			if autoTimestampImportPaths[importPath] {
				autoLabel = "auto-" + alias
				break
			}
		}
		result.MatchedCategories["timestamp"] = []string{autoLabel}
	}

	// A field can match multiple categories (overlap rule).
	for _, cat := range pciDSSFieldCategories {
		for _, field := range fields {
			if matchesCategory(field, cat.Aliases) {
				if _, exists := result.MatchedCategories[cat.Name]; !exists {
					result.MatchedCategories[cat.Name] = []string{field}
				} else {
					// Avoid duplicate field entries.
					alreadyHas := false
					for _, existing := range result.MatchedCategories[cat.Name] {
						if existing == field {
							alreadyHas = true
							break
						}
					}
					if !alreadyHas {
						result.MatchedCategories[cat.Name] = append(result.MatchedCategories[cat.Name], field)
					}
				}
			}
		}
	}

	// Calculate score and missing categories.
	result.Score = len(result.MatchedCategories)
	for _, cat := range pciDSSFieldCategories {
		if _, ok := result.MatchedCategories[cat.Name]; !ok {
			result.MissingCategories = append(result.MissingCategories, cat.Name)
		}
	}

	return result
}

// ScoreSeverity maps a coverage score (0-5) to a scanner.Severity level.
func ScoreSeverity(matched int) scanner.Severity {
	switch {
	case matched >= 3:
		return scanner.SeverityInfo
	case matched >= 1:
		return scanner.SeverityMedium
	default:
		return scanner.SeverityHigh
	}
}

// FormatFieldCoverage produces a human-readable description and suggestion for field coverage.
func FormatFieldCoverage(handlerName string, result *FieldCoverageResult) (description string, suggestion string) {
	// Build "Found:" section.
	var foundParts []string
	// Use stable ordering by iterating pciDSSFieldCategories.
	for _, cat := range pciDSSFieldCategories {
		matched, ok := result.MatchedCategories[cat.Name]
		if !ok {
			continue
		}
		foundParts = append(foundParts, fmt.Sprintf("%s (%s)", cat.Name, strings.Join(matched, ", ")))
	}

	// Build "Missing:" section.
	var missingParts []string
	missingParts = append(missingParts, result.MissingCategories...)

	desc := fmt.Sprintf(
		"Audit log field coverage: %d/%d PCI DSS 10.2.1 fields for handler %s.",
		result.Score, result.Total, handlerName,
	)
	if len(foundParts) > 0 {
		desc += " Found: " + strings.Join(foundParts, ", ") + "."
	}
	if len(missingParts) > 0 {
		desc += " Missing: " + strings.Join(missingParts, ", ") + "."
	}

	switch {
	case result.Score == 5:
		suggestion = "Full PCI DSS 10.2.1 field coverage detected."
	case result.Score >= 3:
		suggestion = fmt.Sprintf("Partial coverage. Consider adding logging for: %s.", strings.Join(missingParts, ", "))
	case result.Score >= 1:
		suggestion = fmt.Sprintf("Insufficient audit log fields for PCI DSS 10.2.1 compliance. Add: %s.", strings.Join(missingParts, ", "))
	default:
		suggestion = "Middleware detected but no PCI DSS audit fields found. Verify logging captures required fields."
	}

	return desc, suggestion
}

// ---------- Field Cache (ALF-05) ----------

// logFieldCache stores resolved field coverage results per middleware function key.
// Key format: "pkgDir::funcName"
var (
	logFieldMu    sync.Mutex
	logFieldCache = map[string]*logFieldCacheEntry{}
)

type logFieldCacheEntry struct {
	fields []string // extracted fields (nil = extraction failed)
	done   bool     // true if extraction was attempted
}

// ResetLogFieldCache clears the field extraction cache between scan sessions.
func ResetLogFieldCache() {
	logFieldMu.Lock()
	logFieldCache = map[string]*logFieldCacheEntry{}
	logFieldMu.Unlock()
}

// ExtractAndScoreLogFields is the main entry point called from auditscanner.go.
// It extracts fields, matches against PCI DSS categories, and returns scoring.
// Returns nil if extraction fails — caller should use generic message.
func ExtractAndScoreLogFields(importPath string, pkgDir string, funcName string) *FieldCoverageResult {
	// Build cache key.
	cacheKey := pkgDir + "::" + funcName

	logFieldMu.Lock()
	if entry, ok := logFieldCache[cacheKey]; ok && entry.done {
		fields := entry.fields
		logFieldMu.Unlock()
		if fields == nil {
			return nil // previously failed
		}
		// Re-score from cached fields — need file imports for timestamp auto-detection.
		// Parse the middleware package to get imports.
		fileImports := resolveMiddlewareImports(importPath, pkgDir)
		return MatchPCIDSSFields(fields, fileImports)
	}
	logFieldMu.Unlock()

	// 1. Resolve import path to on-disk directory.
	modulePath, moduleDir := findGoModule(pkgDir)
	var middlewarePkgDir string
	if modulePath != "" && strings.HasPrefix(importPath, modulePath) {
		relPath := strings.TrimPrefix(importPath, modulePath)
		relPath = strings.TrimPrefix(relPath, "/")
		middlewarePkgDir = filepath.Join(moduleDir, relPath)
	} else {
		// External package, can't follow.
		logFieldMu.Lock()
		logFieldCache[cacheKey] = &logFieldCacheEntry{done: true}
		logFieldMu.Unlock()
		return nil
	}

	// path validation.
	cleanPath := filepath.Clean(middlewarePkgDir)
	if strings.Contains(cleanPath, "..") {
		logFieldMu.Lock()
		logFieldCache[cacheKey] = &logFieldCacheEntry{done: true}
		logFieldMu.Unlock()
		return nil
	}

	// 2. Parse middleware package to get file imports for timestamp auto-detection.
	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, cleanPath)
	if len(pkgFiles) == 0 {
		logFieldMu.Lock()
		logFieldCache[cacheKey] = &logFieldCacheEntry{done: true}
		logFieldMu.Unlock()
		return nil
	}

	// 3. Collect imports from ALL files in the middleware package.
	// The target function (e.g. Install) may be in middleware.go but the actual
	// logger import (e.g. logrus) is in logger.go. We need all imports for
	// timestamp auto-detection.
	fileImports := make(map[string]string)
	for _, file := range pkgFiles {
		for alias, importPath := range buildImportAliases(file) {
			if _, exists := fileImports[alias]; !exists {
				fileImports[alias] = importPath
			}
		}
	}

	// 4. Call ExtractLogFields.
	fields := ExtractLogFields(cleanPath, funcName, fileImports)
	if fields == nil {
		logFieldMu.Lock()
		logFieldCache[cacheKey] = &logFieldCacheEntry{done: true}
		logFieldMu.Unlock()
		return nil
	}

	// 5. Cache fields.
	logFieldMu.Lock()
	logFieldCache[cacheKey] = &logFieldCacheEntry{fields: fields, done: true}
	logFieldMu.Unlock()

	// 6. Match and score.
	return MatchPCIDSSFields(fields, fileImports)
}

// resolveMiddlewareImports resolves a middleware import path to its package directory
// and returns the import aliases from files in that package.
func resolveMiddlewareImports(importPath string, pkgDir string) map[string]string {
	modulePath, moduleDir := findGoModule(pkgDir)
	if modulePath == "" || !strings.HasPrefix(importPath, modulePath) {
		return nil
	}

	relPath := strings.TrimPrefix(importPath, modulePath)
	relPath = strings.TrimPrefix(relPath, "/")
	middlewarePkgDir := filepath.Join(moduleDir, relPath)

	cleanPath := filepath.Clean(middlewarePkgDir)
	if strings.Contains(cleanPath, "..") {
		return nil
	}

	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, cleanPath)
	if len(pkgFiles) == 0 {
		return nil
	}

	// Collect all imports from all files in the package.
	allImports := make(map[string]string)
	for _, file := range pkgFiles {
		aliases := buildImportAliases(file)
		for alias, ip := range aliases {
			allImports[alias] = ip
		}
	}
	return allImports
}

// resolveMiddlewareSource extracts the middleware import path and function name
// from the detection flow. It checks same-package middleware first, then
// cross-package detection from pkgmiddleware.go.
//
// Returns ("", "") if the middleware source cannot be determined (fallback).
func resolveMiddlewareSource(file *ast.File, path string, handlerName string) (importPath string, funcName string) {
	pkgDir := filepath.Dir(path)

	// Strategy 1: Check if a known middleware aggregator import is present in the file.
	// Walk the file's imports looking for packages whose path contains middleware-related segments.
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		ip := strings.Trim(imp.Path.Value, `"`)
		segments := strings.Split(strings.ToLower(ip), "/")
		for _, seg := range segments {
			if seg == "middleware" || seg == "logging" || seg == "logger" {
				// Found a middleware import. Now find which function is called from it.
				alias := filepath.Base(ip)
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				fn := findAggregatorFuncFromImport(file, alias)
				if fn != "" {
					return ip, fn
				}
			}
		}
	}

	// Strategy 2: Check cross-file middleware context for the handler's package.
	ctx := getOrBuildCtx(pkgDir)
	if ctx != nil {
		if groupIdent, ok := ctx.handlerGroups[handlerName]; ok {
			if groupHasCoverage(ctx, groupIdent) {
				// The middleware is in the same package — use the package's own import path.
				modulePath, _ := findGoModule(pkgDir)
				if modulePath != "" {
					// Find an aggregator function with logger arg in the package.
					fn := findAggregatorFuncInPackage(pkgDir)
					if fn != "" {
						relPath := strings.TrimPrefix(pkgDir, filepath.Dir(pkgDir)+"/")
						_ = relPath
						return modulePath + "/" + relPathFromModule(pkgDir, modulePath), fn
					}
				}
			}
		}
	}

	// Strategy 3: Walk parent directories (same as hasLoggingCoverageInPackage).
	current := pkgDir
	for i := 0; i < maxParentWalk; i++ {
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		parentCtx := getOrBuildCtx(parent)
		if parentCtx != nil && parentHasMiddlewareCoveringChild(parentCtx, pkgDir) {
			// Find the middleware import in parent package files.
			ip, fn := findMiddlewareImportInDir(parent)
			if ip != "" {
				return ip, fn
			}
		}
		current = parent
	}

	return "", ""
}

// relPathFromModule calculates the relative import path suffix from a module root.
func relPathFromModule(dir string, modulePath string) string {
	_, moduleDir := findGoModule(dir)
	if moduleDir == "" {
		return ""
	}
	rel := strings.TrimPrefix(dir, moduleDir)
	rel = strings.TrimPrefix(rel, "/")
	return rel
}

// findAggregatorFuncFromImport finds the name of an aggregator function called from a
// package alias in the given file. E.g., for alias "middleware", finds Install in
// middleware.Install(group).
func findAggregatorFuncFromImport(file *ast.File, alias string) string {
	var found string
	ast.Inspect(file, func(n ast.Node) bool {
		if found != "" {
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
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != alias {
			return true
		}
		if aggregatorFuncNames[sel.Sel.Name] {
			found = sel.Sel.Name
			return false
		}
		return true
	})
	return found
}

// findAggregatorFuncInPackage parses a package directory and returns the name of the
// first aggregator function that contains logger-shaped args.
func findAggregatorFuncInPackage(pkgDir string) string {
	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, pkgDir)

	for _, file := range pkgFiles {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			if aggregatorFuncNames[fn.Name.Name] && blockHasLoggerArg(fn.Body) {
				return fn.Name.Name
			}
		}
	}
	return ""
}

// findMiddlewareImportInDir parses all Go files in a directory and finds a middleware
// import path that is used in an aggregator call with logger args.
func findMiddlewareImportInDir(dir string) (importPath string, funcName string) {
	fset := token.NewFileSet()
	pkgFiles := parsePkgFiles(fset, dir)

	for _, file := range pkgFiles {
		imports := buildImportAliases(file)
		for alias, ip := range imports {
			fn := findAggregatorFuncFromImport(file, alias)
			if fn != "" {
				// Verify this import path contains middleware-related segments.
				segments := strings.Split(strings.ToLower(ip), "/")
				for _, seg := range segments {
					if seg == "middleware" || seg == "logging" || seg == "logger" {
						return ip, fn
					}
				}
			}
		}
	}
	return "", ""
}
