package sbomscanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type InventoryResult struct {
	ComponentCount      int
	UnknownLicenseCount int
	HasGoMod            bool
}

func InventoryProbe(projectDir string) (InventoryResult, error) {
	res := InventoryResult{}
	modPath := filepath.Join(projectDir, "go.mod")
	if _, err := os.Stat(modPath); err != nil {
		return res, fmt.Errorf("go.mod not accessible: %w", err)
	}
	res.HasGoMod = true

	if _, err := readIndirectMap(modPath); err != nil {
		return res, fmt.Errorf("go.mod parse: %w", err)
	}

	if _, err := os.Stat(filepath.Join(projectDir, "go.sum")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("go.sum stat: %w", err)
	}

	mods, err := listModules(projectDir)
	if err != nil {
		return res, fmt.Errorf("inventory parse: %w", err)
	}
	res.ComponentCount = len(mods)

	for _, m := range mods {
		if readLicense(m.Path, m.Version) == "UNKNOWN-LICENSE" {
			res.UnknownLicenseCount++
		}
	}
	return res, nil
}
