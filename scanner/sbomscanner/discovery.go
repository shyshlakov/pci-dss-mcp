package sbomscanner

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

type moduleEntry struct {
	Path     string
	Version  string
	Sum      string
	Indirect bool
}

func listModules(projectDir string) ([]moduleEntry, error) {
	abs, err := filepath.Abs(projectDir)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	goSumPath := filepath.Join(abs, "go.sum")
	content, modOnly, err := readGoSumHashes(goSumPath)
	if err != nil {
		return nil, fmt.Errorf("read go.sum: %w", err)
	}
	indirect, err := readIndirectMap(filepath.Join(abs, "go.mod"))
	if err != nil {
		return nil, fmt.Errorf("read go.mod: %w", err)
	}
	keys := make(map[string]struct{}, len(content)+len(modOnly))
	for k := range content {
		keys[k] = struct{}{}
	}
	for k := range modOnly {
		keys[k] = struct{}{}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	out := make([]moduleEntry, 0, len(sorted))
	for _, k := range sorted {
		path, ver, ok := splitModVer(k)
		if !ok {
			continue
		}
		sum := content[k]
		if sum == "" {
			sum = modOnly[k]
		}
		out = append(out, moduleEntry{
			Path:     path,
			Version:  ver,
			Sum:      sum,
			Indirect: indirect[path+" "+ver],
		})
	}
	return out, nil
}

func readGoSumHashes(path string) (content, modOnly map[string]string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	content = make(map[string]string)
	modOnly = make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		mod, ver, sum := fields[0], fields[1], fields[2]
		if strings.HasSuffix(ver, "/go.mod") {
			baseVer := strings.TrimSuffix(ver, "/go.mod")
			modOnly[mod+" "+baseVer] = sum
			continue
		}
		content[mod+" "+ver] = sum
	}
	return content, modOnly, nil
}

func readIndirectMap(goModPath string) (map[string]bool, error) {
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, err
	}
	mf, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.mod: %w", err)
	}
	out := make(map[string]bool, len(mf.Require))
	for _, req := range mf.Require {
		out[req.Mod.Path+" "+req.Mod.Version] = req.Indirect
	}
	return out, nil
}

func splitModVer(key string) (string, string, bool) {
	i := strings.LastIndex(key, " ")
	if i < 0 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

func hashFromH1Sum(sum string) (string, error) {
	if !strings.HasPrefix(sum, "h1:") {
		return "", errors.New("hashFromH1Sum: missing h1: prefix")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sum, "h1:"))
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("decoded length %d, want 32 (SHA-256)", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func buildPURL(modulePath, version string) string {
	return fmt.Sprintf("pkg:golang/%s@%s", modulePath, version)
}

func escapeModulePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
