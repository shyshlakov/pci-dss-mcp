# triage_findings

Run all PCI DSS v4.0.1 scanners plus AI-assisted classification and per-finding file:line context in a single MCP call. This is the recommended entry point for "scan this project" or any open-ended audit prompt. Internally wraps `generate_compliance_report` with AI enrichment that adds triage hints, suggested fixes, and `resource_link` references back to the source file (so MCP clients fetch source on demand instead of receiving inline 20-30 line snippets per finding).

## Parameters

Field names sourced from `scanner/triagescanner/tool.go` `TriageInput`. The 8 params are deliberately identical to `generate_compliance_report` so callers can swap tools without rewriting prompts.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project root containing `go.mod`. Empty defaults to current directory. |
| `dep_scan_mode` | string | no | One of `auto` (default), `online`, `offline`. Passed through to `check_dependencies`. |
| `include_tests` | bool | no | Scan `_test.go` files. Default `false`. |
| `include_taint` | bool | no | Enable flow-based severity adjustment via `go/packages` type analysis. Default `true` (matches `generate_compliance_report` per Phase 19.4 B-13). Set `false` for fast dev iteration. |
| `min_severity` | string | no | One of CRITICAL, HIGH, MEDIUM, LOW, INFO (case-insensitive). Default: no severity filter. Applied BEFORE enrichment to save context-collection cost. Setting this drops the response shape to `flat`. |
| `rule_filter` | string | no | Comma-separated list of rule IDs OR a single regex in leading/trailing slashes (e.g. `/PAN-.*/`). Setting this drops the response shape to `flat`. |
| `limit` | int | no | Maximum findings to enrich per page. Default `0` (summary-first response with `next_cursor`). Above the per-tool page size (12) the server rejects with `LIMIT_EXCEEDS_PAGE_SIZE`; `limit=-1` is rejected with `LIMIT_MINUS_ONE_REMOVED`. |
| `cursor` | string | no | Opaque cursor token from a prior response. Resumes paginated enrichment from the stored session cache (10-minute TTL). Combining `cursor` with new filter or scope params returns `cursor_malformed`. |

## Invocation

Paste into Claude Code, Cursor, or Claude Desktop:

```
Run pci-dss-mcp triage on /Users/me/payments-service. Use min_severity=MEDIUM and group findings by PCI DSS requirement.
```

For a paginated walk through the full result set:

```
Triage /Users/me/payments-service, then follow next_cursor until every finding has been listed.
```

## Rule IDs emitted

Utility tool. Wraps `generate_compliance_report` and adds AI triage enrichment; emits the same rule IDs as the underlying scanner pipeline. See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule_id to requirement_id table.

## PCI DSS requirements covered

All scanned (same as `generate_compliance_report`):

- 3.2.1, 3.3.1, 3.4.1, 3.5.1
- 4.2.1
- 6.2.4, 6.3.2, 6.3.3, 6.4.3
- 8.3.1, 8.3.6, 8.4.2, 8.6.2
- 10.2.1
- 11.6.1

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

Same fixture and baseline as `generate_compliance_report`: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). Triage adds enrichment metadata (triage hint, source `resource_link`s, package decls, middleware chain when relevant) on top of the same per-finding rows. Use the EXPECTED-FINDINGS table as the single source of truth for what triage actually emits today.

## Caveats

- Pairs with `generate_compliance_report` (same scanner pipeline). Do NOT call both for the same scan; triage already runs the report under the hood.
- Per-finding source context is delivered via `resource_link` (file:// URI plus `start_line` / `end_line`) not embedded code snippets (Phase 19.4 B-17). MCP clients fetch source on demand using their own Read tool. Response size for a typical scan is under 50 KB versus ~944 KB pre-19.4.
- AI enrichment may downgrade or upgrade severity within the calibrated false-positive vs recall band. The calibration prefers false positives over silent skips for compliance asymmetry; AI triage absorbs the noise.
- First call per project root pays the 5-30 second taint engine warmup; subsequent calls on the same root are session-cached (10-minute TTL).
- `cursor` is exclusive with new filter or scope params: `min_severity`, `rule_filter`, `limit`, `include_tests`, `dep_scan_mode`, `include_taint` MUST be empty when resuming with a cursor, or the call returns `cursor_malformed`.
