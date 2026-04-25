package sbomscanner

import "encoding/json"

func buildSBOMOutputSchema() (json.RawMessage, error) {
	raw := []byte(`{
  "type": "object",
  "required": ["mode", "bom_format", "spec_version", "component_count", "format", "generated_at", "project_path"],
  "oneOf": [
    {
      "type": "object",
      "properties": {
        "mode": { "const": "file" },
        "output_path": { "type": "string", "description": "Absolute path where the SBOM file was written" },
        "size_bytes":  { "type": "integer", "minimum": 0, "description": "On-disk size of the written SBOM" }
      },
      "required": ["mode", "output_path", "size_bytes"]
    },
    {
      "type": "object",
      "properties": {
        "mode": { "const": "inline" },
        "serialized_bom": { "type": "string", "description": "Compact CycloneDX document (<= 64 KB)" }
      },
      "required": ["mode", "serialized_bom"]
    }
  ],
  "properties": {
    "mode":             { "type": "string", "enum": ["file", "inline"] },
    "bom_format":       { "type": "string", "const": "CycloneDX" },
    "spec_version":     { "type": "string", "const": "1.6" },
    "component_count":  { "type": "integer", "minimum": 0 },
    "unknown_licenses": { "type": "integer", "minimum": 0 },
    "format":           { "type": "string", "enum": ["json", "xml"] },
    "generated_at":     { "type": "string", "description": "RFC3339 UTC" },
    "project_path":     { "type": "string", "description": "Absolute scanned path" },
    "output_path":      { "type": "string" },
    "size_bytes":       { "type": "integer", "minimum": 0 },
    "serialized_bom":   { "type": "string" },
    "fixed_serial":     { "type": "string", "description": "Override generated serialNumber (urn:uuid: or bare 36-char form)" },
    "no_timestamp":     { "type": "boolean", "description": "Omit metadata.timestamp for reproducible builds" }
  }
}`)
	return json.RawMessage(raw), nil
}
