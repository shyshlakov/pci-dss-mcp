package sbomscanner

import (
	"path/filepath"
	"testing"
)

func TestDetectLicense(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name        string
		fixture     string
		wantSPDX    string
		wantSPDXAlt string
		wantMin     float64
	}{
		{name: "mit", fixture: "mit", wantSPDX: "MIT", wantMin: 75.0},
		{name: "apache2", fixture: "apache2", wantSPDX: "Apache-2.0", wantMin: 75.0},
		{name: "bsd3", fixture: "bsd3", wantSPDX: "BSD-3-Clause", wantMin: 75.0},
		{name: "dual_mit_apache", fixture: "dual-mit-apache", wantSPDX: "Apache-2.0", wantSPDXAlt: "MIT", wantMin: 75.0},
		{name: "no_license", fixture: "no-license", wantSPDX: ""},
		{name: "garbage", fixture: "garbage", wantSPDX: ""},
		{name: "partial", fixture: "partial", wantSPDX: ""},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Skipf("Plan 02 wires detectLicense against fixture %s; un-skip when license.go lands", tc.fixture)
			_ = filepath.Join("testdata", "license-fixtures", tc.fixture)
			_ = tc
		})
	}
}
