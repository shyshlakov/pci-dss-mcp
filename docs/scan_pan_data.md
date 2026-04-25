# scan_pan_data

Detects Primary Account Number (PAN) and Sensitive Authentication Data (SAD) handling violations in Go source files. Maps each finding to PCI DSS v4.0.1 requirement 3.3.1 (SAD storage prohibition), 3.4.1 (PAN render unreadable), or 3.5.1 (cryptographic protection). Combines five complementary rules (keyword, type, literal, logger, zeroing) with optional taint analysis that tracks PAN flow through struct fields to filter transit-only data from stored data.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project directory containing `go.mod`. |
| `exclude_patterns` | string[] | no | Glob patterns to skip (directory `vendor/`, file glob `*.pb.go`). Default: `vendor/ generated/ *.pb.go testdata/ mocks/`. |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false`. |
| `include_untracked` | bool | no | Scan all files including `.gitignored`. Default `false` (git-tracked only). |
| `include_taint` | bool | no | Enable flow-based severity adjustment via `go/packages` type analysis. When `true`, PAN-KEYWORD / PAN-TYPE findings on transit-only struct fields are downgraded or suppressed. Adds 5-30 seconds on first call per project root. Default `false` (opt-in for accuracy vs speed). |
| `cursor` | string | no | Opaque cursor token from a prior `scan_pan_data` response. Resumes pagination from the session cache (10-minute TTL). Leave empty for a fresh scan. |
| `limit` | int | no | Maximum findings per call. Default `0` (summary-first response with `next_cursor`). Follow `next_cursor` for subsequent pages; raising `limit` is rejected with `LIMIT_EXCEEDS_PAGE_SIZE`. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Comma list (`PAN-KEYWORD,PAN-TYPE`) or `/regex/` against `rule_id`. Setting this forces the flat response shape. |

Parameter names sourced from `scanner/panscanner/tool.go` (`ScanPANInput`).

## Invocation

In Claude Code or Cursor:

> Run scan_pan_data on /Users/me/payments-service. Use min_severity=MEDIUM and include_taint=true.

## Rule IDs emitted

- `PAN-KEYWORD` - PAN-related keyword in struct field, function name, or string literal.
- `PAN-TYPE` - Custom Go type with PAN-suggestive name declared as `string` (cannot be zeroed).
- `PAN-LITERAL` - String literal matches a Luhn-valid 13-19 digit PAN.
- `PAN-LOGGER` - PAN value flows into a logger call (`slog`, `log`, `fmt.Print*`).
- `PAN-ZEROING` - PAN buffer (`[]byte`) not zeroed after use.

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical `rule_id` to `requirement_id` mapping.

## PCI DSS requirements covered

- `3.3.1` - SAD (CVV/PIN/track data) storage after authorisation prohibited.
- `3.4.1` - PAN rendered unreadable (truncation, masking, hashing, tokenisation).
- `3.5.1` - PAN protected with cryptographic keys.

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `## Violations` table contains rows for `PAN-KEYWORD`, `PAN-TYPE`, `PAN-LITERAL`, `PAN-LOGGER`, and `PAN-ZEROING` (rows starting around `internal/banking/mixed_pan_iban.go` and continuing through `internal/util/cardops.go`).

## Caveats

- Taint analysis adds 5-30 seconds on the first call per project root (subsequent calls in the same session hit the per-root cache). Set `include_taint=false` to skip this cost at the price of recall.
- `PAN-LITERAL` only fires on Luhn-valid 13-19 digit literals. Obfuscated literals (split across concatenations, base64, hex strings) are missed.
- The `requirement_id` reported on each finding is dynamic (PAN field on a stored struct maps to 3.5.1; CVV field maps to 3.3.1). See `docs/requirement-mapping.md` for the resolution rules.
- `PAN-TYPE` flags `string` declarations because `string` is immutable and cannot be zeroed; `[]byte` types are recommended for PAN buffers.
