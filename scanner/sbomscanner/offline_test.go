package sbomscanner

import (
	"context"
	"path/filepath"
	"testing"
)

func TestGenerateSBOM_Offline(t *testing.T) {
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	tt := []struct {
		name               string
		setupEnv           func(t *testing.T)
		gomodcache         func(t *testing.T) string
		wantErr            bool
		wantMinLen         int
		wantUnknownLicense bool
	}{
		{
			name: "primed_cache_no_network",
			setupEnv: func(t *testing.T) {
				t.Setenv("GOPROXY", "off")
				t.Setenv("GOSUMDB", "off")
			},
			wantErr:    false,
			wantMinLen: 40,
		},
		{
			name: "empty_cache_surfaces_unknown_license",
			setupEnv: func(t *testing.T) {
				t.Setenv("GOPROXY", "off")
				t.Setenv("GOSUMDB", "off")
			},
			gomodcache:         func(t *testing.T) string { return t.TempDir() },
			wantErr:            false,
			wantMinLen:         40,
			wantUnknownLicense: true,
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tc.setupEnv(t)
			opts := SBOMOptions{}
			if tc.gomodcache != nil {
				opts.Gomodcache = tc.gomodcache(t)
			}
			sbom, err := GenerateSBOMWithOptions(context.Background(), fixtureRoot, opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err mismatch: got %v wantErr=%v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got := len(sbom.Components); got < tc.wantMinLen {
				t.Errorf("component count: got %d want >=%d", got, tc.wantMinLen)
			}
			if tc.wantUnknownLicense {
				seen := false
				for _, c := range sbom.Components {
					if len(c.Licenses) == 0 {
						seen = true
						break
					}
				}
				if !seen {
					t.Error("expected at least one component without License entries when GOMODCACHE is empty (D-S4)")
				}
			}
		})
	}
}
