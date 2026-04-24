package sbomscanner

import (
	"context"
	"errors"
)

var ErrNotImplemented = errors.New("sbom: not yet implemented")

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
	_ = ctx
	_ = projectDir
	return nil, ErrNotImplemented
}
