package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// initGitRepo creates a temp dir, runs git init, and returns the path.
func initGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init")
	run("config", "user.email", "test@test.com")
	run("config", "user.name", "test")
	return dir
}

func TestGitTrackedFiles(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := initGitRepo(t)
	writeFile(t, filepath.Join(dir, "main.go"), "package main")
	writeFile(t, filepath.Join(dir, "lib.go"), "package main")
	writeFile(t, filepath.Join(dir, "untracked.go"), "package main")

	// Only add main.go and lib.go to git tracking.
	cmd := exec.Command("git", "add", "main.go", "lib.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: true}
	var files []string
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		files = append(files, filepath.Base(path))
	}
	slices.Sort(files)

	// untracked.go should NOT appear.
	expected := []string{"lib.go", "main.go"}
	if !slices.Equal(files, expected) {
		t.Errorf("GitTrackedFiles = %v, want %v", files, expected)
	}
}

func TestGitTrackedFilesFilters(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := initGitRepo(t)
	writeFile(t, filepath.Join(dir, "main.go"), "package main")
	writeFile(t, filepath.Join(dir, "main_test.go"), "package main")
	writeFile(t, filepath.Join(dir, "config.yaml"), "key: val")
	writeFile(t, filepath.Join(dir, "types.pb.go"), "package main // generated")

	cmd := exec.Command("git", "add", ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	// Filter:.go only, exclude _test.go (IncludeTests=false), exclude *.pb.go
	cfg := WalkConfig{
		Extensions:   []string{".go"},
		ExcludeGlobs: []string{"*.pb.go"},
	}
	var files []string
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		files = append(files, filepath.Base(path))
	}

	// Only main.go should pass: config.yaml filtered by extension,
	// main_test.go filtered by IncludeTests=false, types.pb.go by ExcludeGlobs.
	if len(files) != 1 || files[0] != "main.go" {
		t.Errorf("GitTrackedFiles with filters = %v, want [main.go]", files)
	}
}

func TestGitTrackedFilesFallback(t *testing.T) {
	// Use a non-git directory -- should fall back to WalkFiles.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "main.go"), "package main")
	writeFile(t, filepath.Join(dir, "lib.go"), "package lib")

	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: true}
	var files []string
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		files = append(files, filepath.Base(path))
	}
	slices.Sort(files)

	// Fallback to WalkFiles should return both files.
	expected := []string{"lib.go", "main.go"}
	if !slices.Equal(files, expected) {
		t.Errorf("GitTrackedFiles fallback = %v, want %v", files, expected)
	}
}

func TestGitTrackedFilesAbsolutePaths(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := initGitRepo(t)
	writeFile(t, filepath.Join(dir, "main.go"), "package main")

	cmd := exec.Command("git", "add", "main.go")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: true}
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !filepath.IsAbs(path) {
			t.Errorf("GitTrackedFiles returned non-absolute path: %q", path)
		}
	}
}

func TestGitTrackedFilesSkipTestSegmentAtIncludeTestsFalse(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := initGitRepo(t)
	writeFile(t, filepath.Join(dir, "internal", "test", "e2e", "mock.go"), "package e2e")
	writeFile(t, filepath.Join(dir, "internal", "integration", "stripe.go"), "package integration")
	writeFile(t, filepath.Join(dir, "internal", "foo.go"), "package internalpkg")

	cmd := exec.Command("git", "add", ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	resolvedDir, _ := filepath.EvalSymlinks(dir)
	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: false}
	got := make(map[string]bool)
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rel, _ := filepath.Rel(resolvedDir, path)
		got[filepath.ToSlash(rel)] = true
	}

	if got["internal/test/e2e/mock.go"] {
		t.Errorf("internal/test/e2e/mock.go should be skipped at IncludeTests=false")
	}
	if !got["internal/integration/stripe.go"] {
		t.Errorf("internal/integration/stripe.go should be walked (D-03 guard)")
	}
	if !got["internal/foo.go"] {
		t.Errorf("internal/foo.go should be walked")
	}
}

func TestGitTrackedFilesIncludeTestSegmentAtIncludeTestsTrue(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	dir := initGitRepo(t)
	writeFile(t, filepath.Join(dir, "internal", "test", "e2e", "mock.go"), "package e2e")
	writeFile(t, filepath.Join(dir, "internal", "integration", "stripe.go"), "package integration")
	writeFile(t, filepath.Join(dir, "internal", "foo.go"), "package internalpkg")

	cmd := exec.Command("git", "add", ".")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add failed: %v\n%s", err, out)
	}

	resolvedDir, _ := filepath.EvalSymlinks(dir)
	cfg := WalkConfig{Extensions: []string{".go"}, IncludeTests: true}
	got := make(map[string]bool)
	for path, err := range GitTrackedFiles(dir, cfg) {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rel, _ := filepath.Rel(resolvedDir, path)
		got[filepath.ToSlash(rel)] = true
	}

	if !got["internal/test/e2e/mock.go"] {
		t.Errorf("internal/test/e2e/mock.go should be walked at IncludeTests=true")
	}
	if !got["internal/integration/stripe.go"] {
		t.Errorf("internal/integration/stripe.go should be walked")
	}
	if !got["internal/foo.go"] {
		t.Errorf("internal/foo.go should be walked")
	}
}
