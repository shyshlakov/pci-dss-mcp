# check_tls_config

Detects TLS configuration violations in Go source: `InsecureSkipVerify`, missing `MinVersion`, weak `MinVersion` (TLS 1.0 / 1.1), and weak cipher suites (RC4, 3DES, NULL). Maps every finding to PCI DSS v4.0.1 requirement 4.2.1 (strong cryptography for cardholder data in transit). Recognises aliased `tls.Config` field assignments through pointer receivers, including builder patterns.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project directory containing `go.mod`. |
| `exclude_patterns` | string[] | no | Glob patterns to skip (directory `vendor/`, file glob `*.pb.go`). Default: `vendor/ generated/ *.pb.go testdata/ mocks/`. |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false`. |
| `include_untracked` | bool | no | Scan all files including `.gitignored`. Default `false` (git-tracked only). |
| `cursor` | string | no | Opaque cursor token from a prior `check_tls_config` response. Resumes pagination from the session cache (10-minute TTL). Leave empty for a fresh scan. |
| `limit` | int | no | Maximum findings per call. Default `0` (summary-first response with `next_cursor`). Follow `next_cursor` for subsequent pages; raising `limit` is rejected with `LIMIT_EXCEEDS_PAGE_SIZE`. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Comma list (`TLS-INSECURE-SKIP-VERIFY,TLS-WEAK-CIPHER`) or `/regex/` against `rule_id`. Setting this forces the flat response shape. |

Parameter names sourced from `scanner/tlsscanner/tool.go` (`CheckTLSInput`).

## Invocation

In Claude Code or Cursor:

> Run check_tls_config on /Users/me/payments-service.

## Rule IDs emitted

- `TLS-INSECURE-SKIP-VERIFY` - `tls.Config.InsecureSkipVerify = true` (CRITICAL).
- `TLS-MISSING-MIN-VERSION` - No `MinVersion` set on `tls.Config` (defaults to compiler-chosen minimum, typically TLS 1.0 on older toolchains).
- `TLS-WEAK-VERSION` - `MinVersion` set to `tls.VersionTLS10` or `tls.VersionTLS11`.
- `TLS-WEAK-CIPHER` - Weak cipher suite enabled (RC4, 3DES, NULL).

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical `rule_id` to `requirement_id` mapping.

## PCI DSS requirements covered

- `4.2.1` - Strong cryptography for cardholder data in transit (covers all four `TLS-*` rules).

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `## Violations` table contains rows for `TLS-INSECURE-SKIP-VERIFY` (`pkg/visa/client.go`), `TLS-MISSING-MIN-VERSION` (`pkg/mastercard/client.go`, `pkg/visa/client.go`), `TLS-WEAK-CIPHER` (`internal/http/legacy_client.go`), and `TLS-WEAK-VERSION` (`internal/http/legacy_client.go`).

## Caveats

- Test-file false positives are common in mutual-TLS test setups; `include_tests=false` (the default) keeps production-only scans clean.
- Aliased `tls.Config` field assignments through pointer receivers and simple builder patterns are recognised. Deeply nested struct construction or runtime-built configs assembled across multiple packages may be missed by the AST walker.
- `TLS-MISSING-MIN-VERSION` reflects compiler-chosen defaults at the time the binary is built. Pin `MinVersion: tls.VersionTLS12` (or `13`) explicitly to satisfy the rule.
