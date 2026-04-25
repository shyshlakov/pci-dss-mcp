# check_encryption

Detects weak cryptographic primitives, hardcoded encryption keys / IVs, and plain-HTTP transmissions in Go source. Maps each finding to PCI DSS v4.0.1 requirement 6.2.4 (secure cryptographic methods in custom code) or 4.2.1 (strong cryptography for cardholder data in transit). The hardcoded-key detector ships with a five-layer false-positive filter (Phase 19.7) so HTTP header constants, JSON map keys, log field names, and sentinel errors are downgraded rather than treated as live keys.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project directory containing `go.mod`. |
| `exclude_patterns` | string[] | no | Glob patterns to skip (directory `vendor/`, file glob `*.pb.go`). Default: `vendor/ generated/ *.pb.go testdata/ mocks/`. |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false`. |
| `include_untracked` | bool | no | Scan all files including `.gitignored`. Default `false` (git-tracked only). |
| `cursor` | string | no | Opaque cursor token from a prior `check_encryption` response. Resumes pagination from the session cache (10-minute TTL). Leave empty for a fresh scan. |
| `limit` | int | no | Maximum findings per call. Default `0` (summary-first response with `next_cursor`). Follow `next_cursor` for subsequent pages; raising `limit` is rejected with `LIMIT_EXCEEDS_PAGE_SIZE`. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Comma list (`CRYPTO-WEAK-HASH,CRYPTO-PLAIN-HTTP`) or `/regex/` against `rule_id`. Setting this forces the flat response shape. |

Parameter names sourced from `scanner/cryptoscanner/tool.go` (`CheckEncryptionInput`).

## Invocation

In Claude Code or Cursor:

> Run check_encryption on /Users/me/payments-service.

## Rule IDs emitted

- `CRYPTO-WEAK-HASH` - Weak hash function (MD5, SHA-1) used for credentials or other sensitive payloads.
- `CRYPTO-HARDCODED-KEY` - Hardcoded encryption key, IV, or sample key literal in source.
- `CRYPTO-PLAIN-HTTP` - Plain HTTP URL used for a sensitive payload (payment endpoint, API call).

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical `rule_id` to `requirement_id` mapping.

## PCI DSS requirements covered

- `4.2.1` - Strong cryptography for cardholder data in transit (`CRYPTO-PLAIN-HTTP`).
- `6.2.4` - Secure cryptographic methods in custom code (`CRYPTO-WEAK-HASH`, `CRYPTO-HARDCODED-KEY`).

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `## Violations` table contains rows for `CRYPTO-HARDCODED-KEY` (CRITICAL `internal/crypto/keys.go`, HIGH `internal/util/cardops.go`, plus the five-layer downgrade fixtures under `clean/crypto_filter_cases/`), `CRYPTO-PLAIN-HTTP` (`internal/http/client.go`), and `CRYPTO-WEAK-HASH` (`internal/crypto/hash.go`).

## Caveats

- The five-layer `CRYPTO-HARDCODED-KEY` filter (Phase 19.7) suppresses HTTP header names, sentinel errors, log field constants, and JSON map keys. If you see a missed false positive, file an issue with the literal value so the filter rules can be tuned.
- Custom GORM column types implementing `driver.Valuer` + `sql.Scanner` with an encrypt call inside `Value()` are recognised (Phase 19.8) and emit `GORM-ENCRYPT-OK` (INFO, sqlscanner) instead of `GORM-NO-ENCRYPT-HOOK` (HIGH). A defense-in-depth `CRYPTO-HARDCODED-KEY` finding may still fire on the embedded key literal.
- `CRYPTO-PLAIN-HTTP` only fires inside payment-context functions; admin or static-asset HTTP calls are not flagged.
