package authscanner

import (
	"path/filepath"
	"strings"
)

const (
	downgradeTagTestutil    = "testutil_exclusion"
	downgradeReasonTestutil = "Test utility path -- hardcoded credential is fixture infrastructure, not a production secret."
)

var testutilSegments = []string{
	"testutil",
	"testutils",
	"test",
}

func isTestutilPath(path string) bool {
	if path == "" {
		return false
	}
	normalised := strings.ToLower(filepath.ToSlash(path))
	for _, seg := range strings.Split(normalised, "/") {
		for _, want := range testutilSegments {
			if seg == want {
				return true
			}
		}
	}
	return false
}

func testutilTriageHint() string {
	return "downgrade:testutil_exclusion | " + downgradeReasonTestutil
}
