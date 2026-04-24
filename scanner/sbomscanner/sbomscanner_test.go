package sbomscanner

import (
	"context"
	"errors"
	"testing"
)

func TestGenerateSBOMStub(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		path string
	}{
		{name: "empty_path", path: ""},
		{name: "nonexistent", path: "/does/not/exist"},
		{name: "fixture_root", path: "../../testdata/vulnerable-payment-service"},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sbom, err := GenerateSBOM(context.Background(), tc.path)
			if sbom != nil {
				t.Fatalf("expected nil SBOM, got %+v", sbom)
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("expected ErrNotImplemented, got %v", err)
			}
		})
	}
}
