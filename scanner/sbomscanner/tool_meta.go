package sbomscanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/mod/modfile"
)

const (
	toolComponentName = "pci-dss-mcp"
	toolPublisher     = "shyshlakov"
	toolVCSURL        = "https://github.com/shyshlakov/pci-dss-mcp"
	toolDocsURL       = "https://github.com/shyshlakov/pci-dss-mcp#readme"
)

var (
	selfHashOnce  sync.Once
	selfHashValue string
)

func buildToolComponent() cdx.Component {
	c := cdx.Component{
		Type:      cdx.ComponentTypeApplication,
		Name:      toolComponentName,
		Version:   toolVersion(),
		Publisher: toolPublisher,
		ExternalReferences: &[]cdx.ExternalReference{
			{Type: cdx.ERTypeVCS, URL: toolVCSURL},
			{Type: cdx.ERTypeWebsite, URL: toolDocsURL},
		},
	}
	if h := selfHashSHA256(); h != "" {
		c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: h}}
	}
	return c
}

func toolVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "v0.0.0-unknown"
	}
	if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	var rev, ts string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			ts = s.Value
		}
	}
	if rev == "" || ts == "" {
		return "v0.0.0-unknown"
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		ts = t.UTC().Format("20060102150405")
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return fmt.Sprintf("v0.0.0-%s-%s", ts, rev)
}

func isDevelBuild() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return true
	}
	return bi.Main.Version == "" || bi.Main.Version == "(devel)"
}

func selfHashSHA256() string {
	selfHashOnce.Do(func() {
		if isDevelBuild() {
			slog.Warn("sbom self-hash skipped: running from go run / (devel) build")
			return
		}
		exe, err := os.Executable()
		if err != nil {
			slog.Warn("sbom self-hash skipped: os.Executable failed", "err", err)
			return
		}
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		if strings.Contains(exe, os.TempDir()) {
			slog.Warn("sbom self-hash skipped: binary path under TempDir", "path", exe)
			return
		}
		f, err := os.Open(exe)
		if err != nil {
			slog.Warn("sbom self-hash skipped: open failed", "path", exe, "err", err)
			return
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				slog.Warn("sbom self-hash close error", "err", cerr)
			}
		}()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			slog.Warn("sbom self-hash skipped: copy failed", "err", err)
			return
		}
		selfHashValue = hex.EncodeToString(h.Sum(nil))
	})
	return selfHashValue
}

func readMainModulePath(projectDir string) (string, error) {
	path := filepath.Join(projectDir, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	mf, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return "", fmt.Errorf("parse go.mod: %w", err)
	}
	if mf.Module == nil || mf.Module.Mod.Path == "" {
		return "", fmt.Errorf("go.mod has no module directive")
	}
	return mf.Module.Mod.Path, nil
}
