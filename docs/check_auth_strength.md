# check_auth_strength

Detects authentication-strength weaknesses in Go payment service codebases: hardcoded passwords, weak password policies, missing MFA on payment endpoints, byte-vs-character length checks on credential fields, and missing webhook-signature verification on inbound provider callbacks. Maps findings to PCI DSS 8.3.1 (strong cryptography for credentials), 8.3.6 (password complexity), 8.4.2 (MFA for non-console access into the CDE), 8.6.2 (no shared/embedded credentials), and 6.2.4 (secure crypto in custom code, including webhook input validation). Each rule emits the primary requirement plus any related requirements per `docs/requirement-mapping.md`.

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

> Run check_auth_strength on /Users/me/payments-service.

For a filtered flat page:

> Run check_auth_strength on /Users/me/payments-service with min_severity=HIGH and rule_filter=AUTH-WEBHOOK-NO-SIGNATURE.

## Rule IDs emitted

- `AUTH-HARDCODED-PWD` - Hardcoded password literal in source (var, const, `:=`, `os.Setenv`)
- `AUTH-WEAK-POLICY` - Password policy with minimum length below 12 characters
- `AUTH-MISSING-MFA` - Payment-context handler with no MFA middleware gate
- `AUTH-BYTE-COUNT` - Credential length check uses `len()` (byte count) instead of rune counting
- `AUTH-WEBHOOK-NO-SIGNATURE` - Webhook handler parses payload before any signature verification
- `AUTH-WEBHOOK-VERIFIED` - Webhook handler verifies signature before parse (informational positive)

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `8.3.1` - Strong cryptography for credentials at rest and in transit
- `8.3.6` - Password complexity (minimum length, character classes)
- `8.4.2` - MFA for non-console access into the CDE
- `8.6.2` - No shared, group, or embedded credentials
- `6.2.4` - Secure cryptographic methods in custom code (covers webhook input validation)

The `requirement_id` on each finding is dynamic per rule. For example, `AUTH-HARDCODED-PWD` maps to `8.6.2` primary with `8.3.1` related per Phase 19.13 semantics; `AUTH-WEBHOOK-NO-SIGNATURE` maps to `6.2.4`. See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `AUTH-*` rule rows begin near `AUTH-BYTE-COUNT` at line 102 of the `## Violations` table and run through `AUTH-WEBHOOK-VERIFIED` near line 142.

## Caveats

- Server-to-server (S2S) and webhook handlers receive an `AUTH-MISSING-MFA` downgrade to INFO via the multi-signal classifier (Phase 19.9 B-21). PCI DSS 8.4.2 applies to human interactive sessions; machine-to-machine authentication is governed by 8.6 controls and is out of MFA scope.
- Delegation-only handler bodies (single `*.ServeHTTP(w, r)` dispatch wrappers) are skipped to suppress false positives on routing layers (Phase 19.4 B-12).
- The webhook-signature scanner recognises HMAC (`hmac.Equal`), JWS, and RSA verification, plus a 1-level local helper recursion (e.g. `verifyStripeSignature -> hmac.Equal`). Verification must occur before any payload parse to count.
- `AUTH-HARDCODED-PWD` in test-utility paths (`testutil/`, fixture helpers) is downgraded to INFO via the testutil-exclusion classifier; production-path occurrences stay CRITICAL.
- MFA detection is application-layer only. Infrastructure-layer MFA (gateway, service mesh, IdP-enforced step-up) is invisible to a static scanner; QSA review remains the source of truth for 8.4.2 compliance.
