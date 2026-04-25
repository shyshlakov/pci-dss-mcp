# check_dependencies

Detects vulnerable Go module dependencies in `go.mod` by cross-referencing the OSV (Open Source Vulnerabilities) database. Supports three modes: `online` (live OSV API), `offline` (local cache only, suitable for air-gapped environments), and `auto` (default; tries online and falls back to offline). Maps findings to PCI DSS 6.3.3 (security patches for system components and dependencies). The companion utility `update_vulnerability_db` (documented inline below) refreshes the local OSV cache so banks, fintech CI/CD, and air-gapped runners can scan without network access.

## Parameters

Input struct: `CheckDepsInput` (`scanner/depscanner/tool.go:21`).

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the project directory containing `go.mod` |
| `mode` | string | no | One of `auto`, `online`, `offline`. Default `auto` (try online then offline cache). Invalid values return an error. |
| `cursor` | string | no | Opaque pagination cursor from a prior call (10-minute TTL). Cannot be combined with new filters or `limit > 0`. |
| `limit` | int | no | Max findings per page. Default 0 (summary-first response with `next_cursor`); follow the cursor for more. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Restrict to specific rule IDs (comma list or `/regex/`). Setting this forces the flat response shape. |

This scanner does NOT accept `exclude_patterns`, `include_tests`, or `include_untracked` because the only files inspected are `go.mod` and `go.sum` (the dependency manifest is not a source-file scan).

## Invocation

In Claude Code or Cursor:

> Run check_dependencies on /Users/me/payments-service. Use mode=auto.

For an offline scan in an air-gapped runner (after running `update_vulnerability_db` to seed the cache):

> Run check_dependencies on /Users/me/payments-service with mode=offline.

## Rule IDs emitted

- `DEP-VULN` - Vulnerable Go module dependency confirmed against OSV.dev
- `DEP-CACHE-STALE` - Local vulnerability cache exceeds the staleness threshold (7 days = MEDIUM, 14+ days = HIGH)

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `6.3.3` - Security patches and updates are installed for system components, including dependencies, within the v4.0.1 SLAs

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `DEP-VULN` row appears at line 181 of the `## Violations` table.

## Caveats

- The scanner reports against the `go.mod` NEAREST to the supplied scan root (Phase 19.3 B-01). Nested modules under the project root are scanned independently when their own `go.mod` is reached.
- `offline` mode requires a populated cache. Run `update_vulnerability_db` first, or set `mode=auto` so the scanner falls back to the OSV API on cache miss.
- Cache directory default: `~/.pci-dss-mcp/vuln-cache/`. Override via the `PCI_MCP_CACHE_DIR` environment variable. Verified against `scanner/depscanner/cache.go:26` (`cacheEnvVar = "PCI_MCP_CACHE_DIR"`) and `cache.go:27` (`defaultCacheDir = ".pci-dss-mcp/vuln-cache"`); see AUDIT row A-39.
- Phase 21 will introduce call-graph reachability via `golang.org/x/vuln/scan`. Until that ships, every CVE is treated as reachable; unreachable CVEs cannot be downgraded to INFO with call-stack evidence yet.
- `update_vulnerability_db` is the ONLY tool in this MCP server that performs an outbound network request. All other scanners (including this one in `offline` mode) operate purely on local files.

## Companion tool: `update_vulnerability_db`

A second MCP tool registered alongside `check_dependencies` (source: `scanner/depscanner/tool.go:222`, second `mcp.AddTool` block) that refreshes the local OSV vulnerability cache. Combined into this doc per Plan 20.3-04 Claude's Discretion: a single round-trip page covers the full offline workflow.

### Parameters

Input struct: `UpdateDBInput` (`scanner/depscanner/tool.go:30`).

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `output_path` | string | no | Custom directory to write the cache. Default: `~/.pci-dss-mcp/vuln-cache/` (or the value of `PCI_MCP_CACHE_DIR` if set). The cache filename is always `go-osv-YYYY-MM-DD.json`. |

### Output (typed)

Returns `UpdateDBOutput` (`scanner/depscanner/tool.go:34`):

- `cache_path` - Absolute path to the refreshed cache file
- `vuln_count` - Number of vulnerabilities indexed in the new cache
- `download_size_bytes` - Raw download size in bytes
- `previous_cache_date` - Date of the prior cache (`YYYY-MM-DD`); empty when no prior cache existed
- `custom_path` - True when the caller supplied a non-default `output_path`

### Invocation

In Claude Code or Cursor:

> Run update_vulnerability_db.

To write the cache to a custom directory (e.g. a shared CI volume):

> Run update_vulnerability_db with output_path=/srv/pci-cache.

### Caveats

- Downloads from `gs://osv-vulnerabilities/Go/all.zip` (public Google Cloud Storage, ~7.5 MB). Requires outbound HTTPS. In strictly air-gapped environments, mirror the cache directory contents from a connected jump host.
- Cache filename is date-stamped (`go-osv-YYYY-MM-DD.json`); `check_dependencies` resolves the LATEST file by parsed date in the cache directory, ignoring files with unparseable dates.
- No PCI DSS requirement maps directly to this utility; it is operational infrastructure that enables `check_dependencies` (and therefore PCI DSS 6.3.3 evidence) to run offline.
