package triagescanner

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// parsedFile caches AST and raw lines for a single file.
type parsedFile struct {
	astFile *ast.File
	fset    *token.FileSet
	lines   []string
}

// fileCache stores parsed files by absolute path to avoid re-parsing.
type fileCache map[string]*parsedFile

// getParsedGoFile returns a cached parsed Go file, parsing on first access.
// Returns an error if the file cannot be parsed as Go (caller should fall back
// to getFileLines for non-Go files).
func getParsedGoFile(cache fileCache, path string) (*parsedFile, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("abs path %s: %w", path, err)
	}

	if cached, ok := cache[absPath]; ok {
		return cached, nil
	}

	astFile, fset, err := scanner.ParseGoFile(absPath)
	if err != nil {
		return nil, err
	}

	lines, err := readFileLines(absPath)
	if err != nil {
		return nil, fmt.Errorf("read lines %s: %w", absPath, err)
	}

	pf := &parsedFile{
		astFile: astFile,
		fset:    fset,
		lines:   lines,
	}
	cache[absPath] = pf
	return pf, nil
}

// getFileLines returns cached raw lines for a non-Go file.
// If the file is already cached (possibly as a parsed Go file), its lines are returned.
func getFileLines(cache fileCache, path string) ([]string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("abs path %s: %w", path, err)
	}

	if cached, ok := cache[absPath]; ok {
		return cached.lines, nil
	}

	lines, err := readFileLines(absPath)
	if err != nil {
		return nil, err
	}

	// Cache with nil AST fields — this is a non-Go file.
	cache[absPath] = &parsedFile{lines: lines}
	return lines, nil
}

// readFileLines reads all lines of a file into a string slice.
// Local copy of suppression.readFileLines (which is unexported).
func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Warn("close file while reading lines", "path", path, "err", cerr)
		}
	}()

	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, s.Err()
}

// extractImports returns sorted import paths from a parsed Go file.
// Aliased imports are formatted as "alias path".
func extractImports(file *ast.File) []string {
	if file == nil {
		return nil
	}

	imports := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if imp.Name != nil && imp.Name.Name != "_" {
			path = imp.Name.Name + " " + path
		}
		imports = append(imports, path)
	}
	sort.Strings(imports)
	return imports
}

// extractPackageDecls extracts top-level var, const, and type declarations.
// Returns up to 20 entries to limit output size.
func extractPackageDecls(file *ast.File, fset *token.FileSet) []string {
	if file == nil {
		return nil
	}

	const maxDecls = 20
	var decls []string

	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}

		var kind string
		switch genDecl.Tok {
		case token.VAR:
			kind = "var"
		case token.CONST:
			kind = "const"
		case token.TYPE:
			kind = "type"
		default:
			continue
		}

		for _, spec := range genDecl.Specs {
			line := fset.Position(spec.Pos()).Line
			switch s := spec.(type) {
			case *ast.ValueSpec:
				for _, name := range s.Names {
					decls = append(decls, fmt.Sprintf("%s %s at line %d", kind, name.Name, line))
					if len(decls) >= maxDecls {
						return decls
					}
				}
			case *ast.TypeSpec:
				decls = append(decls, fmt.Sprintf("%s %s at line %d", kind, s.Name.Name, line))
				if len(decls) >= maxDecls {
					return decls
				}
			}
		}
	}

	return decls
}

// classifyFileLocation checks path segments for known directory categories.
// Returns a label like "test directory" or empty string if no match.
func classifyFileLocation(filePath string) string {
	segments := strings.Split(filepath.ToSlash(filePath), "/")

	for _, seg := range segments {
		lower := strings.ToLower(seg)
		switch lower {
		case "test", "tests", "testing":
			return "test directory"
		case "testdata":
			return "testdata directory"
		case "dev", "development":
			return "development directory"
		case "example", "examples":
			return "examples directory"
		case "mock", "mocks":
			return "mocks directory"
		case "fixture", "fixtures":
			return "fixtures directory"
		case "vendor":
			return "vendor directory"
		}
	}

	return ""
}
