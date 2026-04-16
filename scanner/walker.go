package scanner

import (
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// WalkConfig controls which files the walker yields.
type WalkConfig struct {
	Extensions  []string // e.g., [".go", ".env", ".yaml"]
	ExcludeDirs []string // additional dirs to exclude (always excludes DefaultExcludeDirs)
	MaxFileSize int64    // skip files larger than this (0 = no limit, default: 10MB)
	// ExcludeGlobs accepts both directory patterns (ending with "/") and file glob
	// patterns (e.g., "*.pb.go"). Directory patterns skip entire subtrees; file
	// patterns use filepath.Match on the base name. This establishes the shared
	// exclude_patterns parameter for all scanners.
	ExcludeGlobs []string
	// IncludeTests controls whether *_test.go files are included in the walk.
	// Default false excludes test files per (industry SAST consensus).
	IncludeTests bool
}

// DefaultExcludeDirs are always excluded from file walks.
var DefaultExcludeDirs = []string{".git", "vendor", "node_modules", "testdata", ".idea", ".vscode"}

// DefaultMaxFileSize is the default maximum file size (10MB).
const DefaultMaxFileSize int64 = 10 * 1024 * 1024

// WalkFiles returns an iterator that yields file paths matching the config.
// It walks root recursively, skipping excluded directories and files that
// don't match the requested extensions or exceed the size limit.
func WalkFiles(root string, cfg WalkConfig) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		// Validate root exists and is a directory.
		info, err := os.Stat(root)
		if err != nil {
			yield("", fmt.Errorf("walker: root path %q: %w", root, err))
			return
		}
		if !info.IsDir() {
			yield("", fmt.Errorf("walker: root path %q is not a directory", root))
			return
		}

		// Build the set of excluded directory names (case-insensitive).
		excluded := make(map[string]bool, len(DefaultExcludeDirs)+len(cfg.ExcludeDirs))
		for _, d := range DefaultExcludeDirs {
			excluded[strings.ToLower(d)] = true
		}
		for _, d := range cfg.ExcludeDirs {
			excluded[strings.ToLower(d)] = true
		}

		// Separate ExcludeGlobs into directory patterns and file patterns.
		var excludeGlobDirs []string
		var excludeGlobFiles []string
		for _, pattern := range cfg.ExcludeGlobs {
			if strings.HasSuffix(pattern, "/") {
				excludeGlobDirs = append(excludeGlobDirs, strings.TrimSuffix(pattern, "/"))
			} else {
				excludeGlobFiles = append(excludeGlobFiles, pattern)
			}
		}

		// Build extension set (case-insensitive).
		extSet := make(map[string]bool, len(cfg.Extensions))
		for _, ext := range cfg.Extensions {
			extSet[strings.ToLower(ext)] = true
		}

		// Resolve effective max file size.
		maxSize := cfg.MaxFileSize
		if maxSize == 0 {
			maxSize = DefaultMaxFileSize
		}

		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// Permission error on a subdirectory: skip it, don't fail the walk.
				if d != nil && d.IsDir() {
					slog.Warn("walker: skipping directory due to error", "path", path, "error", err)
					return fs.SkipDir
				}
				slog.Warn("walker: skipping file due to error", "path", path, "error", err)
				return nil
			}

			// Skip excluded directories.
			if d.IsDir() {
				name := strings.ToLower(d.Name())
				if excluded[name] {
					return fs.SkipDir
				}
				// Check ExcludeGlobs directory patterns.
				for _, dirPattern := range excludeGlobDirs {
					if strings.EqualFold(d.Name(), dirPattern) {
						return fs.SkipDir
					}
				}
				return nil
			}

			// Check ExcludeGlobs file patterns.
			for _, filePattern := range excludeGlobFiles {
				if matched, _ := filepath.Match(filePattern, filepath.Base(path)); matched {
					return nil
				}
			}

			if !cfg.IncludeTests {
				if strings.HasSuffix(filepath.Base(path), "_test.go") {
					return nil
				}
				if hasTestDirSegment(root, path) {
					return nil
				}
			}

			// Filter by extension.
			ext := strings.ToLower(filepath.Ext(path))
			if len(extSet) > 0 && !extSet[ext] {
				return nil
			}

			// Filter by file size.
			if maxSize > 0 {
				fi, fiErr := d.Info()
				if fiErr != nil {
					slog.Warn("walker: cannot stat file, skipping", "path", path, "error", fiErr)
					return nil
				}
				if fi.Size() > maxSize {
					return nil
				}
			}

			// Yield the file path. If yield returns false, stop walking.
			if !yield(path, nil) {
				return filepath.SkipAll
			}
			return nil
		})

		// If WalkDir itself returned an error (not handled above), yield it.
		if walkErr != nil {
			yield("", fmt.Errorf("walker: walking %q: %w", root, walkErr))
		}
	}
}
