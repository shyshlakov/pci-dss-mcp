package depscanner

import (
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
