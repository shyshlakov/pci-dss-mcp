package scanner

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWalkFilesGoOnly(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "config.json"), "{}")
	writeFile(t, filepath.Join(root, "schema.yaml"), "---")
	writeFile(t, filepath.Join(root, "sub", "lib.go"), "package lib")

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 .go files, got %d: %v", len(files), files)
	}
	for _, f := range files {
		if filepath.Ext(f) != ".go" {
			t.Errorf("non-.go file included: %s", f)
		}
	}
}

func TestWalkFilesSkipsGitDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, ".git", "config"), "gitconfig")
	writeFile(t, filepath.Join(root, ".git", "objects", "ab", "file.go"), "package obj")

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "main.go" {
		t.Errorf("expected main.go, got %s", files[0])
	}
}

func TestWalkFilesSkipsVendorDir(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "vendor", "dep", "dep.go"), "package dep")

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), files)
	}
}

func TestWalkFilesSkipsNodeModules(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "node_modules", "pkg", "index.go"), "package pkg")

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), files)
	}
}

func TestWalkFilesMaxFileSize(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "small.go"), "package small")
	// Create a file larger than 100 bytes.
	writeFile(t, filepath.Join(root, "large.go"), string(make([]byte, 200)))

	cfg := WalkConfig{
		Extensions:  []string{".go"},
		MaxFileSize: 100,
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file (small.go), got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "small.go" {
		t.Errorf("expected small.go, got %s", files[0])
	}
}

func TestWalkFilesEmptyDir(t *testing.T) {
	root := t.TempDir()

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 0 {
		t.Fatalf("expected 0 files, got %d: %v", len(files), files)
	}
}

func TestWalkFilesNonexistentDir(t *testing.T) {
	cfg := WalkConfig{Extensions: []string{".go"}}
	_, err := collectWalk("/nonexistent/path/does/not/exist", cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}

func TestWalkFilesExtensionCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.GO"), "package main")
	writeFile(t, filepath.Join(root, "lib.go"), "package lib")

	cfg := WalkConfig{Extensions: []string{".go"}}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files (case-insensitive), got %d: %v", len(files), files)
	}
}

func TestWalkFilesCustomExcludeDirs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "build", "output.go"), "package build")

	cfg := WalkConfig{
		Extensions:  []string{".go"},
		ExcludeDirs: []string{"build"},
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d: %v", len(files), files)
	}
}

func TestWalkFilesExcludeGlobsFilePattern(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "types.pb.go"), "package main // generated")
	writeFile(t, filepath.Join(root, "service.go"), "package main")

	cfg := WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: []string{"*.pb.go"},
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files (excluding *.pb.go), got %d: %v", len(files), files)
	}
	for _, f := range files {
		if filepath.Base(f) == "types.pb.go" {
			t.Errorf("*.pb.go file should have been excluded: %s", f)
		}
	}
}

func TestWalkFilesExcludeGlobsDirPattern(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "generated", "types.go"), "package generated")
	writeFile(t, filepath.Join(root, "generated", "deep", "nested.go"), "package deep")

	cfg := WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: []string{"generated/"},
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file (excluding generated/), got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "main.go" {
		t.Errorf("expected main.go, got %s", files[0])
	}
}

func TestWalkFilesExcludeGlobsCombined(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "types.pb.go"), "package main // generated")
	writeFile(t, filepath.Join(root, "generated", "code.go"), "package generated")
	writeFile(t, filepath.Join(root, "sub", "lib.go"), "package sub")

	cfg := WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: []string{"*.pb.go", "generated/"},
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files (main.go + sub/lib.go), got %d: %v", len(files), files)
	}
	for _, f := range files {
		base := filepath.Base(f)
		if base == "types.pb.go" || base == "code.go" {
			t.Errorf("excluded file should not appear: %s", f)
		}
	}
}

func TestWalkFilesExcludeGlobsEmpty(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "types.pb.go"), "package main // generated")

	cfg := WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: nil,
	}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("empty ExcludeGlobs should not filter anything, expected 2 files, got %d: %v", len(files), files)
	}
}

func TestWalkFilesExcludesTestFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "main_test.go"), "package main")

	cfg := WalkConfig{Extensions: []string{".go"}} // IncludeTests defaults to false
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("expected 1 file (main.go only), got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "main.go" {
		t.Errorf("expected main.go, got %s", files[0])
	}
}

func TestWalkFilesIncludesTestFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.go"), "package main")
	writeFile(t, filepath.Join(root, "main_test.go"), "package main")

	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: true}
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files (both main.go and main_test.go), got %d: %v", len(files), files)
	}
}

func TestWalkFilesTestExclusionOnlyGo(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "config_test.yaml"), "key: value")

	cfg := WalkConfig{Extensions: []string{".yaml"}} // IncludeTests=false
	files, err := collectWalk(root, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// _test.yaml should NOT be excluded -- exclusion only targets.go files.
	if len(files) != 1 {
		t.Fatalf("expected 1 file (config_test.yaml), got %d: %v", len(files), files)
	}
	if filepath.Base(files[0]) != "config_test.yaml" {
		t.Errorf("expected config_test.yaml, got %s", files[0])
	}
}

// collectWalk consumes a WalkFiles iterator and returns all paths or the first error.
func collectWalk(root string, cfg WalkConfig) ([]string, error) {
	var paths []string
	for path, err := range WalkFiles(root, cfg) {
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths, nil
}

// writeFile creates a file at the given path, creating parent dirs as needed.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
