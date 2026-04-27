package depscanner

import (
	"errors"

	_ "github.com/gofrs/flock"
)

// SetOSVZipURL overrides the OSV ZIP download URL for integration testing.
// It returns a cleanup function that restores the original URL.
func SetOSVZipURL(url string) func() {
	original := osvGoZipURL
	osvGoZipURL = url
	return func() {
		osvGoZipURL = original
	}
}

func ResolveCachePathForTest() (string, error) {
	return "", errors.New("ResolveCachePathForTest: not yet implemented")
}
