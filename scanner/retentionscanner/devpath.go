package retentionscanner

import (
	"path/filepath"
	"strings"
)

const (
	downgradeTagDevPath    = "dev_path_skipped"
	downgradeReasonDevPath = "Dev/local/compose/testutil path - retention gap is not a production exposure."
)

var devConfigSegments = []string{
	"dev",
	"local",
	"compose",
	"testutil",
	"testutils",
	"test",
}

func isDevConfigPath(path string) bool {
	if path == "" {
		return false
	}
	normalised := strings.ToLower(filepath.ToSlash(path))
	segments := strings.Split(normalised, "/")
	if len(segments) == 0 {
		return false
	}
	dirSegments := segments[:len(segments)-1]
	for _, seg := range dirSegments {
		if seg == "" {
			continue
		}
		for _, subword := range splitSubwords(seg) {
			for _, want := range devConfigSegments {
				if subword == want {
					return true
				}
			}
		}
	}
	return false
}

func splitSubwords(segment string) []string {
	return strings.FieldsFunc(segment, func(r rune) bool {
		return r == '_' || r == '-'
	})
}

func devPathTriageHint() string {
	return "downgrade:" + downgradeTagDevPath + " | " + downgradeReasonDevPath
}
