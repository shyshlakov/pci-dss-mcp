package sbomscanner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const toolName = "generate_sbom"

const maxInlineBytes = 65536

type GenSBOMInput struct {
	Path   string `json:"path" jsonschema:"required,Absolute path to the Go project directory containing go.mod (and go.sum)"`
	Format string `json:"format,omitempty" jsonschema:"Output format: json (default) or xml. XML is provided for CI tools that prefer CycloneDX XML"`
}

type GenSBOMOutput struct {
	BOMFormat       string `json:"bom_format"`
	SpecVersion     string `json:"spec_version"`
	SerializedBOM   string `json:"serialized_bom"`
	ComponentCount  int    `json:"component_count"`
	UnknownLicenses int    `json:"unknown_licenses,omitempty"`
	Format          string `json:"format"`
	GeneratedAt     string `json:"generated_at"`
	ProjectPath     string `json:"project_path"`
}

func RegisterTools(server *mcp.Server) {
	schema, err := buildSBOMOutputSchema()
	if err != nil {
		slog.Warn("buildSBOMOutputSchema failed", "err", err)
	}
	tool := &mcp.Tool{
		Name: toolName,
		Description: "Generate a CycloneDX v1.5 SBOM for a Go project. " +
			"Parses the project's go.mod + go.sum and resolves modules against the local Go module cache (GOMODCACHE). " +
			"Works offline: no network required as long as the cache is primed. " +
			"Cache-miss modules emit a component with the property UNKNOWN-LICENSE instead of silently dropping. " +
			"Output is a compact (not pretty-printed) CycloneDX document. For typical projects (<= ~200 modules) the SBOM fits in a single MCP response (<= 64 KB). " +
			"Satisfies PCI DSS 6.3.2 (software inventory, mandatory since March 2025).",
		Meta:         mcp.Meta{"anthropic/maxResultSizeChars": 70000},
		OutputSchema: schema,
	}
	mcp.AddTool(server, tool, handleGenerateSBOM)
}

func handleGenerateSBOM(ctx context.Context, req *mcp.CallToolRequest, input GenSBOMInput) (*mcp.CallToolResult, any, error) {
	path := strings.TrimSpace(input.Path)
	if path == "" {
		return errorResult("invalid path: required"), nil, nil
	}
	absPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return errorResult(fmt.Sprintf("invalid path: %v", err)), nil, nil
	}

	format := strings.ToLower(strings.TrimSpace(input.Format))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "xml" {
		return errorResult(`invalid format: must be "json" or "xml"`), nil, nil
	}

	sbom, genErr := GenerateSBOM(ctx, absPath)
	if genErr != nil {
		return errorResult(fmt.Sprintf("sbom generation failed: %v", genErr)), nil, nil
	}

	serialized, unknownCount, serErr := serializeSBOM(sbom, format)
	if serErr != nil {
		return errorResult(fmt.Sprintf("sbom serialization failed: %v", serErr)), nil, nil
	}
	if len(serialized) > maxInlineBytes {
		return errorResult(fmt.Sprintf("SBOM_TOO_LARGE: %d bytes exceeds %d byte inline limit; pagination not yet supported for generate_sbom. Workarounds: invoke cyclonedx-gomod CLI directly, or call sbomscanner.GenerateSBOM from a Go program and write the result to disk.", len(serialized), maxInlineBytes)), nil, nil
	}

	out := &GenSBOMOutput{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.5",
		SerializedBOM:   serialized,
		ComponentCount:  len(sbom.Components),
		UnknownLicenses: unknownCount,
		Format:          format,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		ProjectPath:     absPath,
	}

	payload, err := json.Marshal(out)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal output: %v", err)), nil, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}},
	}, out, nil
}

func serializeSBOM(sbom *SBOM, format string) (string, int, error) {
	bom := ToCycloneDX(sbom)
	unknown := countUnknownLicenses(sbom)
	var buf []byte
	var err error
	switch format {
	case "json":
		buf, err = json.Marshal(bom)
	case "xml":
		buf, err = xml.Marshal(bom)
	default:
		return "", 0, errors.New("unsupported format")
	}
	if err != nil {
		return "", 0, err
	}
	return string(buf), unknown, nil
}

func ToCycloneDX(sbom *SBOM) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_5
	comps := make([]cdx.Component, 0, len(sbom.Components))
	for _, c := range sbom.Components {
		out := cdx.Component{
			Type:       cdx.ComponentTypeLibrary,
			Name:       c.Name,
			Version:    c.Version,
			PackageURL: c.PURL,
		}
		if len(c.Hashes) > 0 {
			hashes := make([]cdx.Hash, 0, len(c.Hashes))
			for _, h := range c.Hashes {
				hashes = append(hashes, cdx.Hash{Algorithm: cdx.HashAlgorithm(h.Algorithm), Value: h.Content})
			}
			out.Hashes = &hashes
		}
		if len(c.Licenses) > 0 {
			lics := cdx.Licenses{}
			unknownOnly := true
			for _, l := range c.Licenses {
				if l.ID == "UNKNOWN-LICENSE" {
					continue
				}
				unknownOnly = false
				lics = append(lics, cdx.LicenseChoice{License: &cdx.License{ID: l.ID}})
			}
			if len(lics) > 0 {
				out.Licenses = &lics
			}
			if unknownOnly {
				props := []cdx.Property{{Name: "UNKNOWN-LICENSE", Value: "cache-miss or unreadable"}}
				out.Properties = &props
			}
		}
		comps = append(comps, out)
	}
	bom.Components = &comps
	return bom
}

func countUnknownLicenses(sbom *SBOM) int {
	n := 0
	for _, c := range sbom.Components {
		for _, l := range c.Licenses {
			if l.ID == "UNKNOWN-LICENSE" {
				n++
				break
			}
		}
	}
	return n
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: msg}},
	}
}
