package sbomscanner

import (
	"context"
	"fmt"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type SBOM struct {
	BOMFormat   string
	SpecVersion string
	Components  []Component
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

func GenerateSBOM(ctx context.Context, projectDir string) (*SBOM, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mods, err := listModules(projectDir)
	if err != nil {
		return nil, fmt.Errorf("sbom discovery: %w", err)
	}
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_5
	bom.Metadata = &cdx.Metadata{
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:      cdx.ComponentTypeApplication,
					Name:      "pci-dss-mcp",
					Publisher: "shyshlakov",
				},
			},
		},
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
		lic := readLicense(m.Path, m.Version)
		if lic == "UNKNOWN-LICENSE" {
			c.Properties = &[]cdx.Property{{Name: "UNKNOWN-LICENSE", Value: "cache-miss or unreadable"}}
		} else {
			c.Licenses = &cdx.Licenses{{License: &cdx.License{ID: lic}}}
		}
		components = append(components, c)
	}
	bom.Components = &components
	return convertBOM(bom), nil
}

func convertBOM(bom *cdx.BOM) *SBOM {
	out := &SBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5"}
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
		if c.Properties != nil {
			for _, p := range *c.Properties {
				if p.Name == "UNKNOWN-LICENSE" {
					comp.Licenses = append(comp.Licenses, License{ID: "UNKNOWN-LICENSE"})
				}
			}
		}
		out.Components = append(out.Components, comp)
	}
	return out
}
