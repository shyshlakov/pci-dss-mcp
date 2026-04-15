package scanner

import (
	"bufio"
	"iter"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitWalkFilter bundles the pre-computed filter state for GitTrackedFiles so
// the per-file check can stay small.
type gitWalkFilter struct {
	extSet           map[string]bool
	excluded         map[string]bool
	excludeGlobFiles []string
	includeTests     bool
	maxSize          int64
}

// GitTrackedFiles returns an iterator over git-tracked files under root that
// match the provided WalkConfig filters. If git is not available or root is not
// inside a git repository, it falls back to WalkFiles.
//
// SECURITY: Uses exec.Command with separate args to prevent command injection.
// Go's exec.Command does not invoke a shell.
func GitTrackedFiles(root string, cfg WalkConfig) iter.Seq2[string, error] {
	absRoot, repoRoot, lsOut, ok := gitLoadTrackedFiles(root)
	if !ok {
		return WalkFiles(root, cfg)
	}
	filter := buildGitWalkFilter(cfg)
	return func(yield func(string, error) bool) {
		scanner := bufio.NewScanner(strings.NewReader(string(lsOut)))
		for scanner.Scan() {
			relPath := scanner.Text()
			if relPath == "" {
				continue
			}
			absPath := filepath.Join(repoRoot, relPath)
			if !isUnderRoot(absPath, absRoot) {
				continue
			}
			if !filter.accepts(absRoot, absPath) {
				continue
			}
			if !yield(absPath, nil) {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			yield("", err)
		}
	}
}

// gitLoadTrackedFiles resolves the repo root, runs git ls-files, and returns
// the resolved absolute root, repo root, and ls-files output. Reports ok=false
// when any precondition fails so the caller can fall back to filesystem walk.
func gitLoadTrackedFiles(root string) (absRoot, repoRoot string, lsOut []byte, ok bool) {
	if _, err := exec.LookPath("git"); err != nil {
		slog.Warn("git not found, falling back to filesystem walk")
		return "", "", nil, false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		slog.Warn("cannot resolve root path, falling back to filesystem walk", "path", root, "error", err)
		return "", "", nil, false
	}
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}
	toplevelOut, err := exec.Command("git", "-C", absRoot, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		slog.Warn("not a git repository, falling back to filesystem walk", "path", absRoot)
		return "", "", nil, false
	}
	repoRoot = strings.TrimSpace(string(toplevelOut))
	lsOut, err = exec.Command("git", "-C", repoRoot, "ls-files", "--cached").Output()
	if err != nil {
		slog.Warn("git ls-files failed, falling back to filesystem walk", "path", absRoot, "error", err)
		return "", "", nil, false
	}
	return absRoot, repoRoot, lsOut, true
}

// buildGitWalkFilter materializes cfg into fast-lookup sets used by accepts.
func buildGitWalkFilter(cfg WalkConfig) gitWalkFilter {
	extSet := make(map[string]bool, len(cfg.Extensions))
	for _, ext := range cfg.Extensions {
		extSet[strings.ToLower(ext)] = true
	}
	excluded := make(map[string]bool, len(DefaultExcludeDirs)+len(cfg.ExcludeDirs))
	for _, d := range DefaultExcludeDirs {
		excluded[strings.ToLower(d)] = true
	}
	for _, d := range cfg.ExcludeDirs {
		excluded[strings.ToLower(d)] = true
	}
	var excludeGlobFiles []string
	for _, pattern := range cfg.ExcludeGlobs {
		if strings.HasSuffix(pattern, "/") {
			excluded[strings.ToLower(strings.TrimSuffix(pattern, "/"))] = true
			continue
		}
		excludeGlobFiles = append(excludeGlobFiles, pattern)
	}
	maxSize := cfg.MaxFileSize
	if maxSize == 0 {
		maxSize = DefaultMaxFileSize
	}
	return gitWalkFilter{
		extSet:           extSet,
		excluded:         excluded,
		excludeGlobFiles: excludeGlobFiles,
		includeTests:     cfg.IncludeTests,
		maxSize:          maxSize,
	}
}

// isUnderRoot reports whether absPath lives inside absRoot (or equals it).
func isUnderRoot(absPath, absRoot string) bool {
	if absPath == absRoot {
		return true
	}
	if strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) {
		return true
	}
	return strings.HasPrefix(absPath, absRoot)
}

// accepts applies all per-file filters: excluded directory segments, test file
// skip, glob patterns, extension match, max size.
func (f gitWalkFilter) accepts(absRoot, absPath string) bool {
	if f.hasExcludedDirSegment(absRoot, absPath) {
		return false
	}
	base := filepath.Base(absPath)
	if !f.includeTests {
		if strings.HasSuffix(base, "_test.go") {
			return false
		}
		if hasTestDirSegment(absRoot, absPath) {
			return false
		}
	}
	if f.matchesExcludeGlob(base) {
		return false
	}
	if len(f.extSet) > 0 {
		ext := strings.ToLower(filepath.Ext(absPath))
		if !f.extSet[ext] {
			return false
		}
	}
	return f.withinSize(absPath)
}

// hasExcludedDirSegment reports true if any dir segment of absPath (relative to
// absRoot) appears in the excluded set.
func (f gitWalkFilter) hasExcludedDirSegment(absRoot, absPath string) bool {
	rel, _ := filepath.Rel(absRoot, absPath)
	for _, part := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if f.excluded[strings.ToLower(part)] {
			return true
		}
	}
	return false
}

// matchesExcludeGlob reports true if base matches any configured file glob.
func (f gitWalkFilter) matchesExcludeGlob(base string) bool {
	for _, pattern := range f.excludeGlobFiles {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
	}
	return false
}

// withinSize reports true if absPath's file size is under the configured max,
// or if stat fails (stat errors are logged and the file is dropped).
func (f gitWalkFilter) withinSize(absPath string) bool {
	if f.maxSize <= 0 {
		return true
	}
	fi, err := os.Stat(absPath)
	if err != nil {
		slog.Warn("cannot stat git-tracked file, skipping", "path", absPath, "error", err)
		return false
	}
	return fi.Size() <= f.maxSize
}
