# Tools Reference

`pci-dss-mcp` exposes 14 user-facing MCP tools (15 registrations including the `update_vulnerability_db` companion). This file is the catalog index plus the migration-note history. For per-tool API reference (parameters, rule IDs, PCI DSS coverage, caveats), see the dedicated `docs/<tool>.md` page linked in the catalog below.

## Catalog

| Tool | One-line purpose | Reference |
|------|------------------|-----------|
| `triage_findings` | All scanners + AI classification + file-line context | [triage_findings.md](triage_findings.md) |
| `generate_compliance_report` | Raw requirement pass/fail report (orchestrator over all scanners) | [generate_compliance_report.md](generate_compliance_report.md) |
| `scan_pan_data` | PAN/SAD storage and logging (3.3.1, 3.4.1, 3.5.1) | [scan_pan_data.md](scan_pan_data.md) |
| `check_encryption` | Weak hashing, hardcoded keys, plain HTTP (4.2.1, 6.2.4) | [check_encryption.md](check_encryption.md) |
| `check_tls_config` | Insecure TLS configs (4.2.1) | [check_tls_config.md](check_tls_config.md) |
| `check_secrets_in_configs` | Credentials in config files (8.6.2) | [check_secrets_in_configs.md](check_secrets_in_configs.md) |
| `check_error_handling` | Error responses leaking sensitive context (6.2.4) | [check_error_handling.md](check_error_handling.md) |
| `check_auth_strength` | Hardcoded passwords, weak policy, missing MFA, webhook signatures (8.3.1, 8.3.6, 8.4.2, 8.6.2) | [check_auth_strength.md](check_auth_strength.md) |
| `audit_log_coverage` | Missing audit logs on payment flows (10.2.1) | [audit_log_coverage.md](audit_log_coverage.md) |
| `check_data_retention` | Missing TTL, sensitive storage, missing zeroing (3.2.1, 3.3.1) | [check_data_retention.md](check_data_retention.md) |
| `check_payment_page_scripts` | Missing CSP/SRI/nonce on payment pages (6.4.3, 11.6.1) | [check_payment_page_scripts.md](check_payment_page_scripts.md) |
| `check_dependencies` | Vulnerable Go dependencies (6.3.3); also covers `update_vulnerability_db` | [check_dependencies.md](check_dependencies.md) |
| `generate_sbom` | CycloneDX 1.6 SBOM (6.3.2) | [generate_sbom.md](generate_sbom.md) |
| `explain_requirement` | Look up a PCI DSS v4.0.1 requirement by ID | [explain_requirement.md](explain_requirement.md) |

For live golden output across all tools, see [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md).

## v0.2.0 migration note (breaking)

As of **v0.2.0**, the default response shape of `generate_compliance_report`
changed from a flat `findings: [...]` array to a summary-first variant
tagged `response_shape: "summary"`. The three tools
`generate_compliance_report`, `triage_findings`, and `scan_pan_data`
now accept an optional `cursor` input parameter for paginated follow-ups.

**To drill into the full findings list progressively**, follow the
`pagination.next_cursor` returned in the default summary response. Each
follow-up call returns 60 findings per page (`FlatResponse`) plus a new
cursor when more pages remain. Cursors are tool-scoped: a cursor issued
by `generate_compliance_report` cannot be replayed against `triage_findings`
(the server returns `CURSOR_MALFORMED`). Session cache TTL is 10 minutes;
expired cursors return `CURSOR_EXPIRED` and the client re-runs without a
cursor to start a fresh scan.

## v0.3.0 migration note (breaking)

As of **v0.3.0**, the default response shape of `triage_findings` and
`scan_pan_data` is now a summary-first variant (`response_shape: "summary"`)
mirroring the v0.2.0 change to `generate_compliance_report`. Unfiltered,
cursor-less calls return severity counts, a per-rule histogram, and a small
`top_findings` map (2 per severity for `triage_findings`, 3 per severity for
`scan_pan_data`), plus a `pagination.next_cursor` for drill-down.

Any filter or scope parameter (`min_severity`, `rule_filter`, `include_tests`,
`include_untracked`, `include_taint`, `exclude_patterns`) switches the
response to the flat shape with cursor pagination.

Both tools declare `_meta["anthropic/maxResultSizeChars"]: 20000` so MCP
clients that recognise the annotation (Claude Code >= v2.1.91) can size
inline rendering in advance. As of v0.3.1 the triage top-N is 1 per severity
and the by_rule histogram is capped at 10 entries (omitted rules counted in
`more_rules`).

## v0.4.0 migration note (breaking)

As of **v0.4.0**, all three hybrid tools (`generate_compliance_report`,
`triage_findings`, `scan_pan_data`) reject `limit: -1` with a structured
error containing the token `LIMIT_MINUS_ONE_REMOVED`. The legacy auto-capped
flat response (max 500 findings in one shot) is no longer callable. Migrate
CI/batch callers to cursor pagination: call with default parameters (or
`min_severity` / `rule_filter` to narrow), then follow
`pagination.next_cursor` until it is empty. The cursor loop handles any
finding volume without a size cap.

## v0.4.1 migration note

As of **v0.4.1**, the Layer A `response_shape: "flat"` variant on all 12
finding-returning tools (`generate_compliance_report`, `triage_findings`,
`scan_pan_data`, `check_encryption`, `check_tls_config`,
`check_secrets_in_configs`, `check_error_handling`, `check_auth_strength`,
`audit_log_coverage`, `check_data_retention`, `check_payment_page_scripts`,
`check_dependencies`) carries a new additive `summary.by_severity` and
`summary.by_rule` block computed over the FULL unfiltered scan. This is
additive only (new optional JSON fields, omitempty) and does not break
clients parsing older responses. A filtered call now answers both "how many
HIGH+ findings" and "what is the full-scan rule/severity breakdown" in a
single shot, so mixed prompts no longer require a second default call to
recover the summary view.

## v0.5.0 migration note

As of **v0.5.0**, four rules emit requirement IDs based on PAN-vs-SAD field
classification instead of a static mapping. Consumers that bucket findings
by `requirement_id` need to update their filters.

Specifically:

- `PAN-KEYWORD`, `PAN-LOGGER`, `SQL-SENSITIVE-COLUMN`, and `GORM-SENSITIVE-TAG`
  findings on PAN fields (`cardNumber`, `pan`, `primary_account_number`,
  `accountNumber`, `ccNo`, `cardNo`) now emit `requirement_id: "3.5.1"`
  (previously `"3.3.1"`). SAD fields (`CVV`, `CVC`, `CID`, `track`, `PIN`)
  continue to emit `"3.3.1"`.
- `PAN-LOGGER` on PAN fields additionally carries
  `related_requirements: ["3.4.1", "10.2.1"]`.
- `AUTH-HARDCODED-PWD` primary `requirement_id` changed from `"8.3.1"` to
  `"8.6.2"`. `"8.3.1"` moved to `related_requirements`.
- `CRYPTO-HARDCODED-KEY` `related_requirements` changed from `["3.6.1.2"]`
  to `["8.6.2"]`. Primary remains `"6.2.4"`.
- `explain_requirement("3.6.1.2")` now returns the correct PCI DSS v4.0.1
  wording ("Secret Key Storage Form": KEK / HSM / key shares). The previous
  embedded text described 3.6.1.3 ("Secret Key Access Restriction").

No severity changes. No new rules. No changes to the 14 MCP tool surface.
For the full canonical rule-to-requirement mapping, see
[docs/requirement-mapping.md](requirement-mapping.md). A Go drift-guard test
in the scanner package fails the build if any rule's source emit diverges
from the canonical table.

## v0.6.0 migration note

SBOM tool added: `generate_sbom` produces CycloneDX 1.5 JSON SBOM from go.mod/go.sum, satisfying mandatory PCI DSS 6.3.2. Tool count increased from 14 to 15 (14 user-facing + 1 companion). The `generate_compliance_report` orchestrator gains a `pci_dss_6_3_2` cross-reference block emitted by `scanner/reportscanner/sbom_inventory.go` that returns PASS when SBOM generation succeeds for the target. SBOM defaults to inline response with a 64 KB guard; oversize returns error token `SBOM_TOO_LARGE`.

## v0.6.1 migration note

`generate_sbom` output mode inverted: writes to file by default at `{path}/sbom.json` (or `.xml`); inline response is opt-in via `inline=true`. New optional parameters: `output_path` (custom file path; absolute-path required, write-permission probed), `inline` (preserves v0.6.0 behavior). New error tokens: `OUTPUT_PATH_NOT_ABSOLUTE`, `OUTPUT_PATH_NOT_WRITABLE`, `DEFAULT_PATH_NOT_WRITABLE`. Migration: callers that depended on the inline default must add `inline=true`. The 64 KB inline guard remains under inline mode.

## v0.6.2 migration note

CycloneDX spec bumped from 1.5 to 1.6 (enables native `License.acknowledgement` field). SPDX license correctness via `google/licensecheck` v0.3.1 at coverage threshold 75; below threshold, license is omitted (not guessed) to avoid SPDX validator rejection. Reproducibility flags added: `fixed_serial` (override `serialNumber` with a deterministic UUID v4; error token `INVALID_FIXED_SERIAL` on invalid input) and `no_timestamp` (omit `metadata.timestamp` for byte-identical output). New emitted fields: `serialNumber` (urn:uuid v4), `metadata.timestamp` (RFC3339 UTC), `metadata.component` (BOM subject), enriched `metadata.tools` with name + version + externalReferences + SHA-256 self-hash. Two B+ hotfixes after release: (a) human-readable 6.3.2 cross-reference no longer carries an unknown-license count; (b) license `acknowledgement` corrected to `concluded` (per spec) instead of `declared` for inferred licenses. Standards-validation gate added: `make test-sbom-validate` invokes `cyclonedx-cli`.

## v0.6.3 migration note (this release)

Documentation reorganized. Each MCP tool now has a dedicated `docs/<tool>.md` page; this `tools.md` becomes the catalog index plus the migration history. README slimmed from ~406 to <=120 lines as a lean landing page. New repo-root `ROADMAP.md` (extracted from README) and `CONTRIBUTING.md` gains fuzz instructions (existing file appended). New advisory drift gate: `make docs-check` (CI step `docs-check (advisory)`) asserts that documented parameter names and error tokens still exist in scanner source code. No scanner code change.
