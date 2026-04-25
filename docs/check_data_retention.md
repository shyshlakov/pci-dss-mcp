# check_data_retention

Detects data-retention violations in Go payment service codebases: Redis writes on sensitive keys without TTL, sensitive column persistence without a retention policy, configuration entries that declare sensitive caches without an expiry, and unsafe sensitive-buffer zeroing patterns (zeroed before authorization completes, zeroed only via `defer`, or zeroed after the response is sent). Maps findings to PCI DSS 3.2.1 (cardholder data retention policy enforcement) and 3.3.1 (Sensitive Authentication Data must not be stored after authorization).

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to Go project root containing go.mod |
| `exclude_patterns` | string[] | no | Glob patterns for files to skip. Default: `vendor/`, `generated/`, `*.pb.go`, `testdata/`, `mocks/` |
| `include_tests` | bool | no | Scan `_test.go` files (default: false) |
| `include_untracked` | bool | no | Scan files not tracked by git (default: false) |
| `cursor` | string | no | Opaque pagination cursor from a prior call (10-minute TTL). Cannot be combined with new filters. |
| `limit` | int | no | Max findings per page. Default 0 (summary-first response with `next_cursor`); follow the cursor for more. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Restrict to specific rule IDs (comma list or `/regex/`). Setting this forces the flat response shape. |

## Invocation

In Claude Code or Cursor:

> Run check_data_retention on /Users/me/payments-service.

For only the SAD-zeroing rules:

> Run check_data_retention on /Users/me/payments-service with rule_filter=/RET-ZERO-/.

## Rule IDs emitted

- `RET-REDIS-NO-TTL` - Redis `SET` on sensitive key without TTL
- `RET-REDIS-KEEP-TTL` - Redis `SET` with `KEEPTTL` on sensitive key (no fresh TTL applied)
- `RET-REDIS-NO-EXPIRE` - Redis `HSET` (or similar) on sensitive key with no nearby `EXPIRE` call
- `RET-DB-SENSITIVE-STORE` - Sensitive column written to DB without an associated retention guard
- `RET-GORM-SENSITIVE-STORE` - GORM model storing a sensitive column without retention/encrypt hook
- `RET-CONFIG-NO-TTL` - Configuration block declares a sensitive cache without `ttl`
- `RET-ZERO-BEFORE-AUTH` - Buffer zeroing executes before the authorization call completes
- `RET-ZERO-DEFER-ONLY` - Zeroing reachable only via `defer` (skipped on panic, late under request scope)
- `RET-ZERO-AFTER-RESPONSE` - Zeroing executed after the HTTP response was already written

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `3.2.1` - Cardholder data retention is minimised; storage time and retention policy are explicit and enforced
- `3.3.1` - Sensitive Authentication Data is not retained after authorization (even if encrypted)

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `RET-*` rule rows begin near `RET-CONFIG-NO-TTL` at line 251 of the `## Violations` table and run through `RET-ZERO-DEFER-ONLY` near line 266.

## Caveats

- `RET-CONFIG-NO-TTL` is downgraded to INFO for dev, local, compose, and testutil paths (Phase 19.5 D-01). Production paths stay HIGH.
- The retention walker recognises zeroing inside `*ast.IfStmt.Init`, `*ast.IfStmt.Else`, `*ast.SwitchStmt`, `*ast.TypeSwitchStmt`, `*ast.CaseClause`, `*ast.SelectStmt`, and `*ast.CommClause` (Phase 19.4 B-11). Zeroing nested deeply inside lambdas or deferred goroutine bodies may still be missed; verify by hand for unusual control flow.
- A SQL `ALTER TABLE ... DROP COLUMN` discovered later in the same migration chain downgrades earlier `RET-DB-SENSITIVE-STORE` and `RET-GORM-SENSITIVE-STORE` findings to INFO (Phase 19.5 D-02). The downgrade applies only when the column-drop migration is statically discoverable.
- The `RET-ZERO-*` rules are advisory for SAD memory lifecycle (PCI DSS 3.3.1 spirit). Static analysis cannot prove a buffer is unreferenced after authorization; use the findings as candidate review points, not as blocking evidence.
- Per `requirement-mapping.md`, every `RET-*` rule carries `partial (static-only, needs QSA)` because retention-policy existence and quarterly review are governance controls a scanner cannot verify.
