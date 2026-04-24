package sbomscanner

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
)

type SBOM struct {
	BOMFormat   string
	SpecVersion string
	Components  []Component
	bom         *cdx.BOM
}

type Component struct {
	Name     string
	Version  string
	PURL     string
	Hashes   []Hash
	Licenses []License
}

type Hash struct {
	Algorithm string
	Content   string
}

type License struct {
	ID string
}

type SBOMOptions struct {
	FixedSerial string
	NoTimestamp bool
	Gomodcache  string
}

var mainModuleWarnOnce sync.Once

func GenerateSBOM(ctx context.Context, projectDir string) (*SBOM, error) {
	return GenerateSBOMWithOptions(ctx, projectDir, SBOMOptions{})
}

func GenerateSBOMWithOptions(ctx context.Context, projectDir string, opts SBOMOptions) (*SBOM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mods, err := listModules(projectDir)
	if err != nil {
		return nil, fmt.Errorf("sbom discovery: %w", err)
	}

	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6

	if opts.FixedSerial != "" {
		u, perr := uuid.Parse(opts.FixedSerial)
		if perr != nil {
			return nil, fmt.Errorf("INVALID_FIXED_SERIAL: %w", perr)
		}
		bom.SerialNumber = u.URN()
	} else {
		bom.SerialNumber = uuid.New().URN()
	}

	mainPath, mainErr := readMainModulePath(projectDir)
	if mainErr != nil {
		mainModuleWarnOnce.Do(func() {
			slog.Warn("sbom main module path: falling back to dir base", "err", mainErr)
		})
		mainPath = filepath.Base(projectDir)
	}
	mainVersion := ""
	mainPURL := buildPURL(mainPath, mainVersion)

	metadata := &cdx.Metadata{
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{buildToolComponent()}},
		Component: &cdx.Component{
			BOMRef:     mainPURL,
			Type:       cdx.ComponentTypeApplication,
			Name:       mainPath,
			Version:    mainVersion,
			PackageURL: mainPURL,
		},
	}
	if !opts.NoTimestamp {
		metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	bom.Metadata = metadata

	gomodcache := opts.Gomodcache
	if gomodcache == "" {
		gomodcache = resolveGomodcache()
	}
	components := make([]cdx.Component, 0, len(mods))
	for _, m := range mods {
		c := cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       m.Path,
			Version:    m.Version,
			PackageURL: buildPURL(m.Path, m.Version),
		}
		if m.Sum != "" {
			if hexHash, hErr := hashFromH1Sum(m.Sum); hErr == nil {
				c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hexHash}}
			}
		}
		attachLicense(&c, detectLicenseIn(gomodcache, m.Path, m.Version))
		components = append(components, c)
	}
	bom.Components = &components

	return convertBOM(bom), nil
}

func convertBOM(bom *cdx.BOM) *SBOM {
	out := &SBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", bom: bom}
	if bom.Components == nil {
		return out
	}
	for _, c := range *bom.Components {
		comp := Component{Name: c.Name, Version: c.Version, PURL: c.PackageURL}
		if c.Hashes != nil {
			for _, h := range *c.Hashes {
				comp.Hashes = append(comp.Hashes, Hash{Algorithm: string(h.Algorithm), Content: h.Value})
			}
		}
		if c.Licenses != nil {
			for _, lc := range *c.Licenses {
				if lc.License != nil {
					comp.Licenses = append(comp.Licenses, License{ID: lc.License.ID})
				}
			}
		}
		out.Components = append(out.Components, comp)
	}
	return out
}
