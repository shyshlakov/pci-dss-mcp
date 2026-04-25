# check_error_handling

Detects payment-handler error disclosure in Go HTTP code: raw `err.Error()` written to the response body, formatted error strings, byte-buffer writes, and JSON-encoded error structs. Maps every finding to PCI DSS v4.0.1 requirement 6.2.4 (information leakage prevention in custom code). Fires only inside payment-context functions, scored by the multi-signal detector (Phase 19.2) so admin handlers and unrelated services do not light up.

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to the Go project directory containing `go.mod`. |
| `exclude_patterns` | string[] | no | Glob patterns to skip (directory `vendor/`, file glob `*.pb.go`). Default: `vendor/ generated/ *.pb.go testdata/ mocks/`. |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false`. |
| `include_untracked` | bool | no | Scan all files including `.gitignored`. Default `false` (git-tracked only). |
| `cursor` | string | no | Opaque cursor token from a prior `check_error_handling` response. Resumes pagination from the session cache (10-minute TTL). Leave empty for a fresh scan. |
| `limit` | int | no | Maximum findings per call. Default `0` (summary-first response with `next_cursor`). Follow `next_cursor` for subsequent pages; raising `limit` is rejected with `LIMIT_EXCEEDS_PAGE_SIZE`. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Comma list (`ERR-LEAK-DIRECT,ERR-LEAK-ENCODE`) or `/regex/` against `rule_id`. Setting this forces the flat response shape. |

Parameter names sourced from `scanner/errorscanner/tool.go` (`CheckErrorHandlingInput`).

## Invocation

In Claude Code or Cursor:

> Run check_error_handling on /Users/me/payments-service.

## Rule IDs emitted

- `ERR-LEAK-DIRECT` - `http.Error(w, err.Error(), ...)` or equivalent direct write of an error value to the HTTP response.
- `ERR-LEAK-FORMAT` - Error value formatted into a response via `fmt.Sprintf`, `fmt.Fprintf`, or similar `%v` / `%s` patterns.
- `ERR-LEAK-WRITE` - Error value byte-coerced and passed to `ResponseWriter.Write` (`w.Write([]byte(err.Error()))`).
- `ERR-LEAK-ENCODE` - Error value encoded into a JSON / XML response body (`json.NewEncoder(w).Encode(err)`, map literals containing `err`).

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical `rule_id` to `requirement_id` mapping.

## PCI DSS requirements covered

- `6.2.4` - Information leakage prevention in custom code (no raw stack traces or internal error strings returned to clients).

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `## Violations` table contains rows for `ERR-LEAK-DIRECT` (`internal/http/handler/tokens/tokenize.go`), `ERR-LEAK-ENCODE` (`internal/billing/encode_map.go`, `internal/http/handler/tokens/metadata.go`), `ERR-LEAK-FORMAT` (`internal/billing/handler.go`, `internal/exchange/handler.go`, `internal/http/handler/tokens/detokenize.go`, `internal/payment/core.go`), and `ERR-LEAK-WRITE` (`internal/http/handler/tokens/exchange.go`).

## Caveats

- The scanner only fires inside payment-context functions per the Phase 19.2 multi-signal scorer. Admin handlers, health checks, and non-payment services are skipped.
- Composite-literal map sinks such as `map[string]any{"error": err}` are recognised (Phase 19.3 B-05 fix) and emit `ERR-LEAK-ENCODE`.
- For non-payment domains where the scorer threshold is too tight or too loose, tune scope via `.pci-mcp-ignore` `exclude-package` directives. See [docs/scoping.md](scoping.md).
