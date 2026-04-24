package sbomscanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInventoryProbe(t *testing.T) {
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}

	emptyDir := t.TempDir()
	if werr := os.WriteFile(filepath.Join(emptyDir, "go.mod"), []byte("module example.com/empty\n\ngo 1.21\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	malformedDir := t.TempDir()
	if werr := os.WriteFile(filepath.Join(malformedDir, "go.mod"), []byte("this is not valid go.mod syntax\nrequire ???\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}

	tt := []struct {
		name           string
		path           string
		wantErr        bool
		wantGoMod      bool
		wantMinComps   int
		wantExactComps int
	}{
		{name: "fixture", path: fixtureRoot, wantErr: false, wantGoMod: true, wantMinComps: 40, wantExactComps: -1},
		{name: "nonexistent", path: "/definitely/does/not/exist/here/999", wantErr: true, wantGoMod: false, wantExactComps: -1},
		{name: "empty_gomod", path: emptyDir, wantErr: false, wantGoMod: true, wantMinComps: 0, wantExactComps: 0},
		{name: "malformed_gomod", path: malformedDir, wantErr: true, wantGoMod: true, wantExactComps: -1},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res, err := InventoryProbe(tc.path)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err: got %v wantErr=%v", err, tc.wantErr)
			}
			if res.HasGoMod != tc.wantGoMod {
				t.Errorf("HasGoMod: got %v want %v", res.HasGoMod, tc.wantGoMod)
			}
			if tc.wantExactComps >= 0 && res.ComponentCount != tc.wantExactComps {
				t.Errorf("ComponentCount: got %d want exactly %d", res.ComponentCount, tc.wantExactComps)
			}
			if tc.wantExactComps < 0 && !tc.wantErr && res.ComponentCount < tc.wantMinComps {
				t.Errorf("ComponentCount: got %d want >=%d", res.ComponentCount, tc.wantMinComps)
			}
		})
	}
}
