# generate_sbom

Generate a CycloneDX 1.6 Software Bill of Materials (SBOM) from a Go project's `go.mod` and `go.sum`. Maps to PCI DSS v4.0.1 §6.3.2 (mandatory software inventory since March 2025). Default behavior writes the SBOM to `{project_path}/sbom.json` and returns metadata only; the inline opt-in (`inline=true`) returns the full SBOM in the MCP response with a 64 KB guard. Reproducibility flags `fixed_serial` and `no_timestamp` enable byte-identical output across runs (SLSA Level 3, CI caching).

## Parameters

Field names sourced from `scanner/sbomscanner/tool.go` `GenSBOMInput` (lines 26-33).

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project directory containing `go.mod` (and `go.sum`). |
| `format` | string | no | Output format: `json` (default) or `xml`. CycloneDX serialization. |
| `output_path` | string | no | Absolute path where the SBOM file should be written. Default `{path}/sbom.json` (or `.xml`). Validated against absolute-path requirement and write-permission probe. Ignored when `inline=true`. Error tokens on failure: `OUTPUT_PATH_NOT_ABSOLUTE`, `OUTPUT_PATH_NOT_WRITABLE`, `OUTPUT_PATH_IS_DIRECTORY`, `DEFAULT_PATH_NOT_WRITABLE`. |
| `inline` | bool | no | If true, return the serialized SBOM inline in the response (64 KB cap; rejected with `SBOM_TOO_LARGE` above the limit). Default: false (write to file and return metadata only). |
| `fixed_serial` | string | no | Override the generated `serialNumber` with a deterministic UUID v4. Accepts bare 36-char form or `urn:uuid:` form. Use for VEX linking and audit pipeline reproducibility. Error token `INVALID_FIXED_SERIAL` if the value is not a valid UUID v4. |
| `no_timestamp` | bool | no | If true, omit `metadata.timestamp` for byte-identical reproducibility. Default: false. |

## Invocation

Paste into Claude Code, Cursor, or Claude Desktop:

```
Generate a CycloneDX SBOM for /Users/me/payments-service.
```

For a reproducible CI build:

```
Run generate_sbom on /Users/me/payments-service with fixed_serial=550e8400-e29b-41d4-a716-446655440000 and no_timestamp=true so the bytes match across runs.
```

## Rule IDs emitted

Utility tool. Does not emit scan findings of its own. `generate_compliance_report` consumes the SBOM via `scanner/reportscanner/sbom_inventory.go` to emit the PCI DSS 6.3.2 cross-reference status (`PASS` when go.mod is parseable and at least one component resolves).

## PCI DSS requirements covered

- `6.3.2` - Software inventory maintained for the cardholder data environment

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See the live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md), section `## SBOM Generation (Phase 20)` (around line 325). The fixture documents the contract: component count floor, required per-component fields (`name`, `version`, `purl`, `hashes`), offline-mode behavior against `$GOMODCACHE`, and the `requirement_status` PASS expectation in `generate_compliance_report`.

## Caveats

- License detection requires a populated `GOMODCACHE`. Set `GOMODCACHE=$HOME/go/pkg/mod` (the default for `go install`-managed installs) before invoking. Modules absent from the cache produce the property `pci-dss-mcp:license-status="unknown"` rather than a guessed SPDX ID.
- `unknown_licenses` count varies with the local cache state; `component_count` is deterministic for a given `go.sum`.
- Read the SBOM JSON, NOT the human-readable summary, for the authoritative per-module license picture.
- The 6.3.2 cross-reference in `generate_compliance_report` no longer carries an unknown-license count (B+ hotfix after Phase 20.2).

## Output shape

Returns `GenSBOMOutput` (`scanner/sbomscanner/tool.go`) with fields:

- `mode` - `file` (default) or `inline`
- `bom_format` - `CycloneDX`
- `spec_version` - `1.6`
- `output_path` - absolute path to the written SBOM (file mode); empty in inline mode
- `size_bytes` - SBOM size in bytes (file mode)
- `serialized_bom` - inline SBOM bytes (inline mode only; under 64 KB)
- `component_count` - total components (direct + transitive)
- `unknown_licenses` - count of components carrying `pci-dss-mcp:license-status="unknown"`
- `format` - echo of the input `format`
- `generated_at` - RFC3339 UTC timestamp (still emitted as a response field even when `no_timestamp=true` strips the SBOM-internal timestamp)
- `project_path` - echo of the input `path` resolved to an absolute path

## Reproducibility

For deterministic output across runs (SLSA Level 3, CI caching, VEX linking):

1. Pin `serialNumber` via `fixed_serial`: pass a stable UUID v4 derived from project + commit (e.g. via `uuidgen` once per release branch). Bare 36-char or `urn:uuid:` forms accepted. Invalid values return `INVALID_FIXED_SERIAL`.
2. Omit `metadata.timestamp` via `no_timestamp=true`.

CLI parity: the `internal/tools/sbomdump` helper exposes `-fixed-serial` and `-no-timestamp` flags for the same effect outside the MCP transport.

## Standards conformance

- **CycloneDX 1.6 JSON** - emitted by default; validated via `cyclonedx-cli` in CI (`make test-sbom-validate`). XML serialization via `format=xml`.
- **SPDX v3.x license IDs** - detected via `google/licensecheck` v0.3.1 at coverage threshold 75 (`licenseCoverageThreshold = 75.0` in `scanner/sbomscanner/license.go`). Below threshold, the license is omitted (not guessed) to avoid SPDX validator rejection.
- **NTIA Minimum Elements for SBOM** - 6 of 7 elements satisfied (component name, version, supplier-as-best-effort, dependency relationship, author, timestamp). The seventh (`unique identifier`) is covered via `bom-ref` plus `purl`.
- **PCI DSS v4.0.1 §6.3.2** - the SBOM satisfies the mandatory software inventory requirement.
- **Tool provenance** - `metadata.tools` includes name, version (from `runtime/debug.ReadBuildInfo`), source repository URL, and a SHA-256 self-hash in `metadata.tools[].externalReferences` (`scanner/sbomscanner/tool_meta.go`). The self-hash is skipped gracefully on `go run` and non-binary execution paths.

## License detection caveats

- License detection traverses `GOMODCACHE` for each component's source. Modules absent from the cache produce `pci-dss-mcp:license-status="unknown"` with no SPDX ID emitted.
- Detected licenses carry `acknowledgement: "concluded"` per CycloneDX 1.6 wording for inferred licenses (B+ hotfix after Phase 20.2 corrected the original `"declared"` value).
- The human-readable 6.3.2 cross-reference in `generate_compliance_report` no longer carries an unknown-license count (B+ hotfix); read the SBOM JSON for per-module status.
- Private or internal modules without a public source can be pre-populated by hand into `GOMODCACHE` so the licensecheck scanner can read their LICENSE files.
- For a `licensecheck` panic the scanner logs `licensecheck panic recovered; reporting empty coverage` and treats the module as unknown rather than crashing the SBOM run.
