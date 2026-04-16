package sqlscanner

import (
	"go/ast"
	"go/token"
	"strings"
)

const RuleGormEncryptOK = "GORM-ENCRYPT-OK"

type valuerTypeInfo struct {
	TypeName    string
	ValueDecl   *ast.FuncDecl
	ScanDecl    *ast.FuncDecl
	FilePath    string
	FileImports map[string]string
}

type pkgFuncEntry struct {
	Decl    *ast.FuncDecl
	Imports map[string]string
}

var strongSignalCalls = map[string]map[string]bool{
	"crypto/aes":                           {"NewCipher": true},
	"crypto/cipher":                        {"NewGCM": true, "NewCBCEncrypter": true},
	"crypto/rand":                          {"Read": true},
	"crypto/hmac":                          {"New": true},
	"golang.org/x/crypto/nacl/secretbox":   {"Seal": true},
	"golang.org/x/crypto/chacha20poly1305": {"New": true, "NewX": true},
	"github.com/google/tink/go/aead":       {"Encrypt": true},
}

var kmsReceiverSubstrings = []string{
	"kms", "vault", "hsm", "barbican", "secretmanager", "keymanager",
}

var kmsMethodNames = map[string]bool{
	"Encrypt":            true,
	"EncryptCtx":         true,
	"EncryptWithContext": true,
	"Seal":               true,
	"Wrap":               true,
}

func isValuerSignature(fn *ast.FuncDecl) bool {
	if fn.Name == nil || fn.Name.Name != "Value" {
		return false
	}
	if fn.Type == nil {
		return false
	}
	if fn.Type.Params != nil && len(fn.Type.Params.List) > 0 {
		return false
	}
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}
	return true
}

func isGormValuerSignature(fn *ast.FuncDecl) bool {
	if fn.Name == nil || fn.Name.Name != "GormValue" {
		return false
	}
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	if len(fn.Type.Params.List) < 1 {
		return false
	}
	return true
}

func isScannerSignature(fn *ast.FuncDecl) bool {
	if fn.Name == nil || fn.Name.Name != "Scan" {
		return false
	}
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	if len(fn.Type.Params.List) != 1 {
		return false
	}
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	return true
}

func buildAllImports(file *ast.File) map[string]string {
	out := map[string]string{}
	if file == nil {
		return out
	}
	for _, imp := range file.Imports {
		if imp == nil || imp.Path == nil {
			continue
		}
		path := strings.Trim(imp.Path.Value, `"`)
		var alias string
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				continue
			}
			alias = imp.Name.Name
		} else {
			parts := strings.Split(path, "/")
			alias = parts[len(parts)-1]
		}
		out[alias] = path
	}
	return out
}

func collectPkgFuncs(file *ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	if file == nil {
		return out
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Recv != nil {
			continue
		}
		if fn.Name == nil {
			continue
		}
		out[fn.Name.Name] = fn
	}
	return out
}

func collectPkgFuncEntries(file *ast.File) map[string]pkgFuncEntry {
	out := map[string]pkgFuncEntry{}
	if file == nil {
		return out
	}
	imports := buildAllImports(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil {
			continue
		}
		out[fn.Name.Name] = pkgFuncEntry{Decl: fn, Imports: imports}
	}
	return out
}

func buildVerifiedTypeMap(file *ast.File, fset *token.FileSet, filePath string) map[string]*valuerTypeInfo {
	_ = fset
	out := map[string]*valuerTypeInfo{}
	if file == nil {
		return out
	}
	imports := buildAllImports(file)

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		recvType := receiverTypeName(fn.Recv)
		if recvType == "" {
			continue
		}

		entry := out[recvType]
		switch {
		case isValuerSignature(fn) || isGormValuerSignature(fn):
			if entry == nil {
				entry = &valuerTypeInfo{
					TypeName:    recvType,
					FilePath:    filePath,
					FileImports: imports,
				}
				out[recvType] = entry
			}
			entry.ValueDecl = fn
		case isScannerSignature(fn):
			if entry == nil {
				entry = &valuerTypeInfo{
					TypeName:    recvType,
					FilePath:    filePath,
					FileImports: imports,
				}
				out[recvType] = entry
			}
			entry.ScanDecl = fn
		}
	}

	for k, v := range out {
		if v.ValueDecl == nil {
			delete(out, k)
		}
	}
	return out
}

func verifyValueBody(vt *valuerTypeInfo, pkgFuncs map[string]*ast.FuncDecl) (bool, string) {
	if vt == nil || vt.ValueDecl == nil || vt.ValueDecl.Body == nil {
		return false, ""
	}
	entries := pkgFuncEntriesFromDecls(pkgFuncs)
	visited := map[string]bool{}
	if vt.ValueDecl.Name != nil {
		visited[vt.ValueDecl.Name.Name] = true
	}
	return checkBodyForCrypto(vt.ValueDecl.Body, vt.FileImports, entries, visited, 1)
}

func verifyValueBodyEntries(vt *valuerTypeInfo, pkgFuncs map[string]pkgFuncEntry) (bool, string) {
	if vt == nil || vt.ValueDecl == nil || vt.ValueDecl.Body == nil {
		return false, ""
	}
	visited := map[string]bool{}
	if vt.ValueDecl.Name != nil {
		visited[vt.ValueDecl.Name.Name] = true
	}
	return checkBodyForCrypto(vt.ValueDecl.Body, vt.FileImports, pkgFuncs, visited, 1)
}

func pkgFuncEntriesFromDecls(decls map[string]*ast.FuncDecl) map[string]pkgFuncEntry {
	out := map[string]pkgFuncEntry{}
	for name, fn := range decls {
		out[name] = pkgFuncEntry{Decl: fn, Imports: nil}
	}
	return out
}

func checkBodyForCrypto(body *ast.BlockStmt, imports map[string]string, pkgFuncs map[string]pkgFuncEntry, visited map[string]bool, depthBudget int) (bool, string) {
	if body == nil {
		return false, ""
	}
	verified := false
	hit := ""

	ast.Inspect(body, func(n ast.Node) bool {
		if verified {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if v, h := matchSelectorCrypto(fn, imports); v {
				verified, hit = true, h
				return false
			}
			if v, h := matchKMSCall(fn); v {
				verified, hit = true, h
				return false
			}
		case *ast.Ident:
			if depthBudget <= 0 {
				return true
			}
			if visited[fn.Name] {
				return true
			}
			helper, ok := pkgFuncs[fn.Name]
			if !ok || helper.Decl == nil || helper.Decl.Body == nil {
				return true
			}
			visited[fn.Name] = true
			helperImports := helper.Imports
			if helperImports == nil {
				helperImports = imports
			}
			if v, h := checkBodyForCrypto(helper.Decl.Body, helperImports, pkgFuncs, visited, depthBudget-1); v {
				verified, hit = true, h
				return false
			}
		}
		return true
	})

	return verified, hit
}

func matchSelectorCrypto(sel *ast.SelectorExpr, imports map[string]string) (bool, string) {
	if sel == nil || sel.Sel == nil {
		return false, ""
	}
	pkgIdent, ok := sel.X.(*ast.Ident)
	if !ok {
		return false, ""
	}
	importPath, found := imports[pkgIdent.Name]
	if !found {
		return false, ""
	}
	calls, found := strongSignalCalls[importPath]
	if !found {
		return false, ""
	}
	if calls[sel.Sel.Name] {
		return true, pkgIdent.Name + "." + sel.Sel.Name
	}
	return false, ""
}

func matchKMSCall(sel *ast.SelectorExpr) (bool, string) {
	if sel == nil || sel.Sel == nil {
		return false, ""
	}
	if !kmsMethodNames[sel.Sel.Name] {
		return false, ""
	}
	receiverHint := receiverHintString(sel.X)
	if receiverHint == "" {
		return false, ""
	}
	lower := strings.ToLower(receiverHint)
	for _, sub := range kmsReceiverSubstrings {
		if strings.Contains(lower, sub) {
			return true, "KMS:" + sel.Sel.Name
		}
	}
	return false, ""
}

func receiverHintString(expr ast.Expr) string {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		left := receiverHintString(x.X)
		if x.Sel == nil {
			return left
		}
		if left == "" {
			return x.Sel.Name
		}
		return left + "." + x.Sel.Name
	case *ast.CallExpr:
		return receiverHintString(x.Fun)
	case *ast.StarExpr:
		return receiverHintString(x.X)
	}
	return ""
}

func bareTypeName(fieldType string) string {
	t := strings.TrimSpace(fieldType)
	for {
		switch {
		case strings.HasPrefix(t, "*"):
			t = t[1:]
		case strings.HasPrefix(t, "[]"):
			t = t[2:]
		default:
			if i := strings.LastIndex(t, "."); i >= 0 {
				t = t[i+1:]
			}
			return t
		}
	}
}
