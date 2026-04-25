# check_secrets_in_configs

Detects hardcoded credentials, API keys, tokens, and connection strings with embedded credentials in configuration files (`.env`, `.yaml`, `.json`, `.toml`). Maps every finding to PCI DSS v4.0.1 requirement 8.6.2 (passwords / passphrases for application or system accounts must not be embedded in source or configuration). Pairs prefix matching, high-entropy detection, connection-string parsing, and credential-key inference; downgrades obvious dev / example fixtures rather than dropping them, so an auditor sees what was checked.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the project directory containing config files. |
| `exclude_patterns` | string[] | no | Glob patterns to skip (directory `vendor/`, file glob `*.env`). Default: `vendor/ generated/ *.pb.go testdata/ mocks/`. |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false`. |
| `include_untracked` | bool | no | Scan all files including `.gitignored`. Default `false` (git-tracked only). |
| `cursor` | string | no | Opaque cursor token from a prior `check_secrets_in_configs` response. Resumes pagination from the session cache (10-minute TTL). Leave empty for a fresh scan. |
| `limit` | int | no | Maximum findings per call. Default `0` (summary-first response with `next_cursor`). Follow `next_cursor` for subsequent pages; raising `limit` is rejected with `LIMIT_EXCEEDS_PAGE_SIZE`. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Comma list (`SEC-CONNSTR,SEC-PREFIX`) or `/regex/` against `rule_id`. Setting this forces the flat response shape. |

Parameter names sourced from `scanner/secretscanner/tool.go` (`CheckSecretsInput`).

## Invocation

In Claude Code or Cursor:

> Run check_secrets_in_configs on /Users/me/payments-service.

## Rule IDs emitted

- `SEC-PREFIX` - Known provider prefix detected in a config value (`sk_live_`, `AKIA`, `ghp_`, etc.).
- `SEC-HIGH-ENTROPY` - High-entropy literal in a config value (likely embedded secret).
- `SEC-CONNSTR` - Database / queue connection string with embedded credentials (e.g. `postgres://user:pass@host`).
- `SEC-CREDENTIAL-KEY` - Field name suggests a credential (`password`, `api_key`, `token`, `secret`, etc.) in `.env`, `.yaml`, `.json`, or `.toml`.

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical `rule_id` to `requirement_id` mapping.

## PCI DSS requirements covered

- `8.6.2` - Passwords / passphrases for application or system accounts must not be embedded in source code or configuration.

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `## Violations` table contains rows for `SEC-CONNSTR` (`configs/database.yaml`), `SEC-CREDENTIAL-KEY` (`configs/auth.toml`, `configs/service.env`, `configs/service.yaml`, plus the `clean/examples/` and `configs/dev/` downgrade fixtures), `SEC-HIGH-ENTROPY` (`configs/service.yaml`), and `SEC-PREFIX` (`configs/service.yaml`).

## Caveats

- Credentials in `examples/`, `samples/`, or `docs/examples/` paths are downgraded to INFO with `TriageHint: dev_path_examples_skipped` (Phase 19.6). Production paths and `prod-*` filenames stay at CRITICAL.
- High-entropy detection has a length floor; very short tokens (under 12 characters) are not flagged because false-positive density becomes too high.
- Use the suppression file `.pci-mcp-ignore` to declare known dev / test fixtures or rotate noisy keys with an audit-trail entry. See [docs/scoping.md](scoping.md).
