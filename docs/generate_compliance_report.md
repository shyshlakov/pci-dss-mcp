# generate_compliance_report

Orchestrator MCP tool that runs all 12 PCI DSS v4.0.1 scanners (PAN, crypto, TLS, secrets, error, auth, audit, retention, script, dep, SBOM, sql) and aggregates their findings into a single compliance report. The response uses the v0.2.0 hybrid response shape: a summary-first payload (Layer B) with totals, per-rule and per-severity histograms, plus cursor pagination (Layer A) for drill-down. Use this tool for CI gates, audit artifacts, and raw requirement pass/fail lists. Do NOT call it in addition to `triage_findings`; triage already runs the same scanner pipeline and adds AI enrichment on top.

## Parameters

Field names sourced from `scanner/reportscanner/tool.go` `ReportInput`.

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project root containing `go.mod`. Empty defaults to current directory. |
| `dep_scan_mode` | string | no | One of `auto` (default), `online`, `offline`. Passed through to `check_dependencies`; controls whether the OSV vulnerability database is fetched over the network. |
| `include_tests` | bool | no | Scan `_test.go` files. Default `false` per industry SAST consensus. |
| `include_taint` | bool | no | Enable flow-based severity adjustment via `go/packages` type analysis. Default `true` (production-grade precision); set `false` for fast dev iteration. Adds 5-30 seconds for the first call per project root. |
| `min_severity` | string | no | One of CRITICAL, HIGH, MEDIUM, LOW, INFO (case-insensitive). Default: no severity filter. Setting this drops the response shape to `flat`. |
| `rule_filter` | string | no | Comma-separated list of rule IDs for exact match (e.g. `PAN-KEYWORD,PAN-TYPE`) OR a single regex in leading/trailing slashes (e.g. `/PAN-.*/`). Setting this drops the response shape to `flat`. |
| `limit` | int | no | Maximum findings per page. Default `0` (summary-first response with `next_cursor`). The server rejects values above the per-tool page size with `LIMIT_EXCEEDS_PAGE_SIZE`; `limit=-1` is rejected with `LIMIT_MINUS_ONE_REMOVED`. |
| `cursor` | string | no | Opaque pagination cursor from a prior response. Resumes from the stored session cache (10-minute TTL). |

## Invocation

Paste into Claude Code, Cursor, or Claude Desktop:

```
Generate a PCI DSS compliance report for /Users/me/payments-service.
```

For a CI-style filtered report:

```
Run generate_compliance_report on /Users/me/payments-service with min_severity=HIGH and follow the cursor for every page.
```

## Rule IDs emitted

Orchestrator. Emits findings from all 12 scanners and has no rule IDs of its own. See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule_id to requirement_id table covering every emitted rule.

## PCI DSS requirements covered

All scanned by the underlying scanner pipeline:

- 3.2.1, 3.3.1, 3.4.1, 3.5.1
- 4.2.1
- 6.2.4, 6.3.2 (SBOM cross-reference), 6.3.3, 6.4.3
- 8.3.1, 8.3.6, 8.4.2, 8.6.2
- 10.2.1
- 11.6.1

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See the live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The full `## Violations` table contains every per-finding row produced by this tool against the canonical fixture; the `## Summary` block records the canonical baseline (CRITICAL=49, HIGH=89, MEDIUM=27, LOW=0, INFO=59 with taint enabled). Use that file as the single source of truth for what `generate_compliance_report` actually emits today.

## Caveats

- Pairs with `triage_findings` (same scanner pipeline plus AI enrichment). Do NOT call both for the same scan.
- Taint analysis defaults to ON (Phase 19.3 B-09); pass `include_taint=false` for the fast path.
- The summary-first response returns counts and per-rule/per-severity aggregates first; pass `cursor` to drill into specific finding pages.
- Includes a `pci_dss_6_3_2` cross-reference block in `requirement_status`. Status is `PASS` when `generate_sbom` succeeds for this project root (go.mod present, parseable, at least one dependency). The cross-reference no longer carries an unknown-license count (B+ hotfix after Phase 20.2); read the SBOM JSON directly for per-module license status.
- First call per project root pays the 5-30 second taint engine warmup; subsequent calls on the same root are session-cached (10-minute TTL).
