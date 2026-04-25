package sbomscanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzGoModSBOM(f *testing.F) {
	f.Add([]byte("module example.com/m\n\ngo 1.21\n"), []byte(""))
	f.Add(
		[]byte("module example.com/m\n\ngo 1.21\n\nrequire github.com/x/y v1.0.0\n"),
		[]byte("github.com/x/y v1.0.0 h1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab=\ngithub.com/x/y v1.0.0/go.mod h1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab=\n"),
	)

	f.Fuzz(func(t *testing.T, gomod []byte, gosum []byte) {
		tmpdir := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmpdir, "go.mod"), gomod, 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		if len(gosum) > 0 {
			if err := os.WriteFile(filepath.Join(tmpdir, "go.sum"), gosum, 0o600); err != nil {
				t.Fatalf("write go.sum: %v", err)
			}
		}

		mods, modsErr := listModules(tmpdir)
		if mods != nil && modsErr != nil {
			t.Fatalf("listModules invariant broken: both non-nil mods=%v err=%v", mods, modsErr)
		}

		if modsErr == nil {
			for _, m := range mods {
				if m.Sum != "" {
					if _, err := hashFromH1Sum(m.Sum); err != nil {
						_ = err
					}
				}
			}
		}

		if _, err := GenerateSBOM(context.Background(), tmpdir); err != nil {
			_ = err
		}
	})
}
