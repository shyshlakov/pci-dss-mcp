# explain_requirement

Look up a single PCI DSS v4.0.1 requirement by ID and return its full text, applicability, and pci-dss-mcp detection notes. Use this whenever you have a `requirement_id` from another tool's finding and want the requirement record without leaving the IDE.

## Parameters

Field name sourced from `pcidb/tool.go` `ExplainInput`.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `requirement_id` | string | yes | PCI DSS v4.0.1 requirement ID (e.g. `3.3.1`, `8.6.2`, `6.3.2`). Whitespace trimmed before lookup. Unknown IDs return `Unknown requirement ID:...` with hint to use `3.3.1` / `8.3.6` / `6.4.3` style. |

## Invocation

Paste into Claude Code, Cursor, or Claude Desktop:

```
Look up PCI DSS requirement 3.3.1 using explain_requirement.
```

Or chained after a scan:

```
For each requirement_id in the previous report, call explain_requirement and quote the official wording before suggesting a remediation.
```

## Output shape

Returns an `ExplainRequirementOutput` struct from `pcidb/tool.go` with a single `requirement` field carrying the full `*Requirement` record from `pcidb/pcidb.go`. Fields:

- `requirement_id` - the ID, e.g. `3.3.1`
- `title` - short label, e.g. "Sensitive Authentication Data Not Stored After Authorization"
- `description` - official PCI DSS v4.0.1 text
- `testing_procedure` - how a QSA validates the requirement
- `severity` - PCI DSS severity classification
- `detectable` - whether pci-dss-mcp has scanner coverage for this requirement
- `new_in_v4` - true if introduced in PCI DSS v4.0 / v4.0.1
- `coverage_scope`, `limitations`, `not_covered` - accuracy metadata for detectable requirements
- `covered_by`, `not_detectable_reason`, `requires_qsa` - NOT_CHECKED metadata for sub-requirements that fold into a parent scanner or that need a human QSA

## PCI DSS requirements covered

Every entry present in the embedded `pcidb/data/pci-dss-v4.0.1.json` (250 requirement records as of v0.6.2). See [docs/pci-coverage.md](pci-coverage.md) for the matrix of which of those requirements pci-dss-mcp actively detects via the scanner pipeline.

## Caveats

- The pcidb is embedded at build time via `//go:embed pcidb/data/pci-dss-v4.0.1.json`. Values are stable per binary version; rebuild the binary to pick up upstream PCI DSS errata.
- Some requirements (e.g. 3.6.1.2 secret-key storage form, 12.x program-level governance) are marked `detectable: false, requires_qsa: true` per Phase 19.13 D-04. Use the `requires_qsa` field on the returned record to decide whether a finding needs automated remediation, manual QSA review, or both.
- Utility tool: emits no scanner findings of its own. For a scan, call `triage_findings` (recommended) or `generate_compliance_report` (CI gate).
