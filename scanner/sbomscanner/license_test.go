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
			fixtureDir, err := filepath.Abs(filepath.Join("testdata", "license-fixtures", tc.fixture))
			if err != nil {
				t.Fatalf("abs: %v", err)
			}
			got := detectLicenseFromPath(fixtureDir)
			if tc.wantSPDX == "" {
				if got.SPDXID != "" {
					t.Errorf("SPDXID: got %q want empty (low-coverage / cache-miss case)", got.SPDXID)
				}
				return
			}
			if tc.wantSPDXAlt != "" {
				if got.SPDXID != tc.wantSPDX && got.SPDXID != tc.wantSPDXAlt {
					t.Errorf("SPDXID: got %q want %q or %q", got.SPDXID, tc.wantSPDX, tc.wantSPDXAlt)
				}
			} else if got.SPDXID != tc.wantSPDX {
				t.Errorf("SPDXID: got %q want %q", got.SPDXID, tc.wantSPDX)
			}
			if got.Confidence < tc.wantMin {
				t.Errorf("Confidence: got %.2f want >= %.2f", got.Confidence, tc.wantMin)
			}
		})
	}
}
