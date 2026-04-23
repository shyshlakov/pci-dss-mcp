package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func FuzzWalker(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("package p"))
	f.Add([]byte("package p\nfunc F() {}\n"))
	f.Add([]byte("package p\ntype T struct { F string `json:\"f\"` }\n"))
	f.Add([]byte("package p\nfunc F() { _ = 1 + }\n"))
	f.Add([]byte("package p\nfunc F[T any](x T) T { return x }\n"))
	f.Add([]byte("package p\nimport \"fmt\"\nfunc F() { fmt.Println(\"4111111111111111\") }\n"))
	f.Add([]byte("\x00\x00\x00"))
	f.Add([]byte("package\tp"))

	f.Fuzz(func(t *testing.T, src []byte) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "fuzz.go", src, parser.ParseComments)
		if err != nil && file == nil {
			return
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				_ = n.Fun
				_ = len(n.Args)
			case *ast.SelectorExpr:
				if n.Sel != nil {
					_ = n.Sel.Name
				}
			case *ast.Ident:
				_ = n.Name
			case *ast.StructType:
				if n.Fields != nil {
					for _, field := range n.Fields.List {
						for _, name := range field.Names {
							_ = name.Name
						}
					}
				}
			case *ast.BasicLit:
				_ = n.Value
			}
			return true
		})
	})
}
