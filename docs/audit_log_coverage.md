# audit_log_coverage

Detects payment-context handlers and admin endpoints that lack audit logging or use unstructured logs (e.g. `fmt.Println`, `log.Printf`) without the structured key fields a PCI DSS audit trail requires. Maps findings to PCI DSS 10.2.1 (audit logs for all individual user access to cardholder data and all administrative actions). Verified-OK structured-logging hits are emitted as INFO so QSA reviewers see positive evidence, not just absence.

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

> Run audit_log_coverage on /Users/me/payments-service.

For a filtered flat page focused on critical handlers:

> Run audit_log_coverage on /Users/me/payments-service with min_severity=HIGH.

## Rule IDs emitted

- `AUDIT-NO-LOG` - Payment-context handler with no audit log statement on the request path
- `AUDIT-UNSTRUCTURED` - Audit log present but unstructured (e.g. `fmt.Println`, `log.Printf`); no required fields set
- `AUDIT-LOG-OK` - Structured audit log with required fields detected (informational positive)

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `10.2.1` - Audit logs are enabled and active for all individual user access to cardholder data and all administrative actions

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `AUDIT-*` rule rows begin at `AUDIT-LOG-OK` line 75 of the `## Violations` table and run through `AUDIT-UNSTRUCTURED` near line 101.

## Caveats

- The scanner only fires inside payment-context functions (Phase 19.2 multi-signal scorer). Domains outside the CDE perimeter are not flagged. If your project has logging-sensitive code outside payment context that you want covered, raise it in scoping config.
- `AUDIT-LOG-OK` is INFO-level. The verified-OK marker exists so auditors can see that something was checked, not silently skipped (see scanner-design philosophy: INFO for verified-OK).
- Field completeness (user_id, timestamp, action, outcome, origin per PCI DSS 10.2.1) is NOT statically verified beyond detecting structured logging. QSA review remains the source of truth for log-record completeness; see `requirement-mapping.md` `partial (static-only, needs QSA)` annotation on `AUDIT-NO-LOG`.
- Required field set per AUDIT rule is encoded in `scanner/auditscanner/`. Consult the scanner source for the exact key names the structured-log detection accepts (logrus, slog, zap field forms).
