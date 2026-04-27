# check_dependencies

Cross-references your `go.mod` against the public OSV (Open Source Vulnerabilities) database to detect known CVEs in your Go dependencies. Maps findings to PCI DSS 6.3.3. The scanner uses a govulncheck-style privacy model: it bulk-downloads the public OSV Go vulnerability snapshot once, then intersects locally against your go.mod. Module names are never sent to OSV.dev. The companion utility `update_vulnerability_db` (documented inline below) refreshes the local OSV cache so banks, fintech CI/CD, and air-gapped runners can scan without network access.

## Parameters

Input struct: `CheckDepsInput` (`scanner/depscanner/tool.go:21`).

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the project directory containing `go.mod` |
| `mode` | string | no | Only `auto` is supported (default). The `online` and `offline` keywords were removed in v0.6.3. Other values return an error. |
| `cursor` | string | no | Opaque pagination cursor from a prior call (10-minute TTL). Cannot be combined with new filters or `limit > 0`. |
| `limit` | int | no | Max findings per page. Default 0 (summary-first response with `next_cursor`); follow the cursor for more. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Restrict to specific rule IDs (comma list or `/regex/`). Setting this forces the flat response shape. |

This scanner does NOT accept `exclude_patterns`, `include_tests`, or `include_untracked` because the only files inspected are `go.mod` and `go.sum` (the dependency manifest is not a source-file scan).

## Invocation

In Claude Code or Cursor:

> Run check_dependencies on /Users/me/payments-service.

`mode` defaults to `auto`; passing it explicitly is optional. See [Privacy](#privacy) for the cache-first scan model.

## Rule IDs emitted

- `DEP-VULN` - Vulnerable Go module dependency confirmed against OSV.dev
- `DEP-CACHE-COLD` - INFO: vulnerability cache is empty AND network refresh failed. Run with network access OR bind-mount the cache directory.
- `DEP-CACHE-STALE` - INFO: vulnerability cache exists but is stale AND network refresh failed. Cache age is reported in the description.
- `DEP-CACHE-NO-DIR` - INFO: cache directory cannot be determined. Set PCI_MCP_CACHE_DIR to a writable path.

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `6.3.3` - Security patches and updates are installed for system components, including dependencies, within the v4.0.1 SLAs

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `DEP-VULN` row appears at line 181 of the `## Violations` table.

## Privacy

The dependency scanner uses the same privacy model as Go's official `govulncheck` tool: it bulk-downloads the public OSV Go vulnerability snapshot from `storage.googleapis.com/osv-vulnerabilities/Go/all.zip` and intersects locally against your `go.mod`. The only outbound network request is a generic GET on this public URL, indistinguishable from any other govulncheck user.

What this means for your codebase:

- No Go module names (private or public) are sent to OSV.dev.
- Internal module paths (e.g., `gitlab.example.com/internal/billing`) stay on your host.
- GOPRIVATE configuration is not required for privacy. The scanner is privacy-correct by default.
- Inside Docker, the privacy guarantee holds even when GOPRIVATE / GOPROXY env vars are not propagated into the container.

The previous `online` and `offline` mode keywords (which used a POST endpoint that sent module names) were removed in v0.6.3. Callers passing those keywords now receive a migration error.

## Cache architecture

- 0-24h: cache is fresh. Scan reads from disk. Zero outbound HTTP.
- 24h-7d: scan sends a conditional GET (`If-None-Match` + `If-Modified-Since`). HTTP 304 = cache reused. HTTP 200 = cache replaced atomically.
- greater than 7d: scan force-refreshes via a full GET. The cache file is replaced atomically.
- Parallel scans against the same cache path are race-free: a cross-platform advisory file lock guards the refresh write region.
- Stale fallback: if the network call during refresh fails (TTL >24h AND offline), the scanner emits a `DEP-CACHE-STALE` INFO finding and continues with the existing cache. Findings produced from stale data are still valid (the cache simply lacks recent CVEs).

## Offline operation

The scanner is designed for air-gapped CI runners (banks, fintech CI/CD).

Cold cache + no network: emits `DEP-CACHE-COLD` INFO. No DEP-VULN findings produced (no data to intersect against). Action: run `update_vulnerability_db` once on a connected jump host or bind-mount a populated cache directory.

Stale cache + no network: emits `DEP-CACHE-STALE` INFO with cache age. DEP-VULN findings produced from existing data. Action: run `update_vulnerability_db` from a connected host or extend the bind-mount to allow refresh.

No writable cache directory: emits `DEP-CACHE-NO-DIR` INFO. No findings produced. Action: set `PCI_MCP_CACHE_DIR` to a writable path.

## Environment variables

- `PCI_MCP_CACHE_DIR` - explicit cache directory. Highest precedence. No default.
- `XDG_CACHE_HOME` - Linux convention. If set and absolute, the scanner uses `$XDG_CACHE_HOME/pci-dss-mcp/vuln-cache`. Relative values are skipped (per XDG spec quirk).
- `OSV_BASE_URL` - override the OSV snapshot base URL. Used by enterprise mirrors of OSV.dev (PCI-strict banks). Default unchanged. The override URL must point at a trusted OSV mirror under your control.

Cache directory resolution order (top wins):

1. `PCI_MCP_CACHE_DIR`
2. `XDG_CACHE_HOME/pci-dss-mcp/vuln-cache` (Linux convention. Absolute paths only)
3. `$HOME/.pci-dss-mcp/vuln-cache` (legacy default. Preserves back-compat for existing users)
4. `os.UserCacheDir()/pci-dss-mcp/vuln-cache` (`~/Library/Caches` on macOS, `%LocalAppData%` on Windows)
5. Hard-fail: `DEP-CACHE-NO-DIR` INFO finding emitted

## Persisting the cache across container runs

```bash
docker run --rm \
  --mount type=bind,src=$HOME/.pci-dss-mcp,dst=/root/.pci-dss-mcp \
  ghcr.io/shyshlakov/pci-dss-mcp:latest \
  check_dependencies /workspace
```

Without this bind-mount, every `docker run --rm` loses the cache and re-downloads the ~8MB snapshot.

WSL2 / PowerShell: when invoking from PowerShell, write the source as a Windows path: `--mount type=bind,src="C:\Users\<you>\.pci-dss-mcp",dst=/root/.pci-dss-mcp`. Running from a WSL2 shell, the canonical Linux form above works as-is.

SELinux (Fedora/RHEL): add the `:Z` short-form mount option, e.g. `-v $HOME/.pci-dss-mcp:/root/.pci-dss-mcp:Z`. The long-form `--mount` does not accept `:Z`.

Linux non-root user: container UID 0 (root) writes files owned by host UID 0 by default. Either run the container with `--user $(id -u):$(id -g)` or `chown -R $(id -u):$(id -g) ~/.pci-dss-mcp` after the first scan.

## Caveats

- The scanner reports against the `go.mod` NEAREST to the supplied scan root (Phase 19.3 B-01). Nested modules under the project root are scanned independently when their own `go.mod` is reached.
- All scans go through the local OSV cache. Run `update_vulnerability_db` once with network access to bootstrap the cache for air-gapped environments.
- Cache directory default: `~/.pci-dss-mcp/vuln-cache/`. Override via the `PCI_MCP_CACHE_DIR` environment variable. Verified against `scanner/depscanner/cache.go:26` (`cacheEnvVar = "PCI_MCP_CACHE_DIR"`) and `cache.go:27` (`defaultCacheDir = ".pci-dss-mcp/vuln-cache"`); see AUDIT row A-39.
- Phase 21 will introduce call-graph reachability via `golang.org/x/vuln/scan`. Until that ships, every CVE is treated as reachable; unreachable CVEs cannot be downgraded to INFO with call-stack evidence yet.
- `update_vulnerability_db` is the ONLY tool in this MCP server that performs an outbound network request as a primary purpose. `check_dependencies` itself goes through the local OSV cache; refreshes happen only via the conditional-GET path described in [Cache architecture](#cache-architecture).

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
