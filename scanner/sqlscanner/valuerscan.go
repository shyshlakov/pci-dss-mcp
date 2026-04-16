package sqlscanner

import (
	"go/ast"
	"go/token"
)

const RuleGormEncryptOK = "GORM-ENCRYPT-OK"

type valuerTypeInfo struct {
	TypeName    string
	ValueDecl   *ast.FuncDecl
	ScanDecl    *ast.FuncDecl
	FilePath    string
	FileImports map[string]string
}

func buildVerifiedTypeMap(file *ast.File, fset *token.FileSet, filePath string) map[string]*valuerTypeInfo {
	_ = file
	_ = fset
	_ = filePath
	return map[string]*valuerTypeInfo{}
}

func buildAllImports(file *ast.File) map[string]string {
	_ = file
	return map[string]string{}
}

func collectPkgFuncs(file *ast.File) map[string]*ast.FuncDecl {
	_ = file
	return map[string]*ast.FuncDecl{}
}

func verifyValueBody(vt *valuerTypeInfo, pkgFuncs map[string]*ast.FuncDecl) (bool, string) {
	_ = vt
	_ = pkgFuncs
	return false, ""
}
