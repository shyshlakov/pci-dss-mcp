package scanner

import (
	"path/filepath"
	"strings"
)

var testDirSegments = []string{"test", "testing", "mocks", "fixtures", "e2e"}

func hasTestDirSegment(root, path string) bool {
	rel := path
	if root != "" {
		if r, err := filepath.Rel(root, path); err == nil {
			rel = r
		}
	}
	normalized := filepath.ToSlash(rel)
	for _, seg := range strings.Split(normalized, "/") {
		for _, tok := range testDirSegments {
			if seg == tok {
				return true
			}
		}
	}
	return false
}
