package sbomscanner

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const toolName = "generate_sbom"

const maxInlineBytes = 65536

type GenSBOMInput struct {
	Path        string `json:"path" jsonschema:"required,Absolute path to the Go project directory containing go.mod (and go.sum)"`
	Format      string `json:"format,omitempty" jsonschema:"Output format: json (default) or xml"`
	OutputPath  string `json:"output_path,omitempty" jsonschema:"Absolute path where the SBOM file should be written. Default: {path}/sbom.json or {path}/sbom.xml. Ignored when inline=true."`
	Inline      bool   `json:"inline,omitempty" jsonschema:"If true, return serialized SBOM inline in the response (64 KB cap, SBOM_TOO_LARGE on overflow). Default: false, write to file and return metadata only."`
	FixedSerial string `json:"fixed_serial,omitempty" jsonschema:"Override generated serialNumber. Accepts bare UUID v4 or urn:uuid: form. Use for VEX linking and audit pipeline reproducibility."`
	NoTimestamp bool   `json:"no_timestamp,omitempty" jsonschema:"If true, omit metadata.timestamp for reproducible builds."`
}

type GenSBOMOutput struct {
	Mode            string `json:"mode"`
	BOMFormat       string `json:"bom_format"`
	SpecVersion     string `json:"spec_version"`
	OutputPath      string `json:"output_path,omitempty"`
	SizeBytes       int64  `json:"size_bytes,omitempty"`
	SerializedBOM   string `json:"serialized_bom,omitempty"`
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
		Description: "Generate a CycloneDX v1.6 SBOM for a Go project. " +
			"Default behavior: writes sbom.json (or sbom.xml when format=xml) next to the scanned go.mod and returns metadata only (output_path, size_bytes, component_count, unknown_licenses). " +
			"Override the destination with output_path (must be absolute). " +
			"Pass inline=true to return the serialized SBOM in the MCP response instead (capped at 64 KB; returns SBOM_TOO_LARGE above that). " +
			"Parses go.mod + go.sum offline against the local GOMODCACHE; cache-miss modules surface as UNKNOWN-LICENSE. " +
			"Satisfies PCI DSS 6.3.2 (software inventory, mandatory since March 2025).",
		Meta:         mcp.Meta{"anthropic/maxResultSizeChars": 70000},
		OutputSchema: schema,
	}
	mcp.AddTool(server, tool, HandleGenerateSBOM)
}

func HandleGenerateSBOM(ctx context.Context, req *mcp.CallToolRequest, input GenSBOMInput) (*mcp.CallToolResult, any, error) {
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

	opts := SBOMOptions{NoTimestamp: input.NoTimestamp}
	if strings.TrimSpace(input.FixedSerial) != "" {
		if _, perr := uuid.Parse(input.FixedSerial); perr != nil {
			return errorResult(fmt.Sprintf("INVALID_FIXED_SERIAL: %q is not a valid UUID v4 (accepted: bare 36-char form or urn:uuid: form): %v", input.FixedSerial, perr)), nil, nil
		}
		opts.FixedSerial = input.FixedSerial
	}

	sbom, genErr := GenerateSBOMWithOptions(ctx, absPath, opts)
	if genErr != nil {
		return errorResult(fmt.Sprintf("sbom generation failed: %v", genErr)), nil, nil
	}

	serialized, unknownCount, serErr := serializeSBOM(sbom, format)
	if serErr != nil {
		return errorResult(fmt.Sprintf("sbom serialization failed: %v", serErr)), nil, nil
	}

	nowRFC3339 := time.Now().UTC().Format(time.RFC3339)

	if input.Inline {
		if len(serialized) > maxInlineBytes {
			return errorResult(fmt.Sprintf("SBOM_TOO_LARGE: %d bytes exceeds %d byte inline limit; drop inline=true to write the SBOM to disk instead.", len(serialized), maxInlineBytes)), nil, nil
		}
		out := &GenSBOMOutput{
			Mode:            "inline",
			BOMFormat:       "CycloneDX",
			SpecVersion:     "1.6",
			SerializedBOM:   serialized,
			ComponentCount:  len(sbom.Components),
			UnknownLicenses: unknownCount,
			Format:          format,
			GeneratedAt:     nowRFC3339,
			ProjectPath:     absPath,
		}
		return wrapPayload(out)
	}

	resolvedPath, usingDefault, resolveErr := resolveOutputPath(absPath, input.OutputPath, format)
	if resolveErr != nil {
		return errorResult(resolveErr.Error()), nil, nil
	}
	if werr := os.WriteFile(resolvedPath, []byte(serialized), 0o644); werr != nil {
		tok := "OUTPUT_PATH_NOT_WRITABLE"
		if usingDefault {
			tok = "DEFAULT_PATH_NOT_WRITABLE"
		}
		if errors.Is(werr, syscall.EISDIR) {
			return errorResult(fmt.Sprintf("OUTPUT_PATH_IS_DIRECTORY: %q is an existing directory; provide a file path", resolvedPath)), nil, nil
		}
		if errors.Is(werr, fs.ErrPermission) || errors.Is(werr, fs.ErrNotExist) {
			return errorResult(fmt.Sprintf("%s: cannot write to %q: %v (pass output_path to override)", tok, resolvedPath, werr)), nil, nil
		}
		return errorResult(fmt.Sprintf("sbom write failed: %v", werr)), nil, nil
	}
	out := &GenSBOMOutput{
		Mode:            "file",
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.6",
		OutputPath:      resolvedPath,
		SizeBytes:       int64(len(serialized)),
		ComponentCount:  len(sbom.Components),
		UnknownLicenses: unknownCount,
		Format:          format,
		GeneratedAt:     nowRFC3339,
		ProjectPath:     absPath,
	}
	return wrapPayload(out)
}

func wrapPayload(out *GenSBOMOutput) (*mcp.CallToolResult, any, error) {
	payload, err := json.Marshal(out)
	if err != nil {
		return errorResult(fmt.Sprintf("marshal output: %v", err)), nil, nil
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}},
	}, out, nil
}

func resolveOutputPath(scanTarget, userProvided, format string) (string, bool, error) {
	ext := ".json"
	if format == "xml" {
		ext = ".xml"
	}

	var resolved string
	usingDefault := false
	if strings.TrimSpace(userProvided) == "" {
		resolved = filepath.Join(scanTarget, "sbom"+ext)
		usingDefault = true
	} else {
		if !filepath.IsAbs(userProvided) {
			return "", false, fmt.Errorf("OUTPUT_PATH_NOT_ABSOLUTE: %q is not an absolute path", userProvided)
		}
		resolved = filepath.Clean(userProvided)
	}

	if info, err := os.Stat(resolved); err == nil && info.IsDir() {
		return "", usingDefault, fmt.Errorf("OUTPUT_PATH_IS_DIRECTORY: %q is an existing directory; provide a file path", resolved)
	}

	return resolved, usingDefault, nil
}

func serializeSBOM(sbom *SBOM, format string) (string, int, error) {
	bom := sbom.bom
	if bom == nil {
		bom = ToCycloneDX(sbom)
	}
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
	bom.SpecVersion = cdx.SpecVersion1_6
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
