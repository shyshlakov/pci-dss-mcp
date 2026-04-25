# check_payment_page_scripts

Detects missing or weakened script-integrity controls on payment pages: missing or unsafe Content-Security-Policy headers (including `unsafe-inline`/`unsafe-eval`), missing Subresource Integrity (SRI) on external scripts, missing nonces on inline scripts, and the file integrity monitoring (FIM) advisory required for consumer-facing payment pages. Reads both Go HTTP-handler header writes and HTML template files. Maps findings to PCI DSS 6.4.3 (payment page script inventory and integrity controls) and 11.6.1 (change/tamper detection on consumer-facing payment pages).

## Parameters

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `path` | string | yes | Absolute path to project root containing go.mod (Go handlers) and any HTML templates |
| `exclude_patterns` | string[] | no | Glob patterns for files to skip. Default: `vendor/`, `generated/`, `*.pb.go`, `testdata/`, `mocks/` |
| `include_tests` | bool | no | Scan `_test.go` files (default: false) |
| `include_untracked` | bool | no | Scan files not tracked by git (default: false) |
| `cursor` | string | no | Opaque pagination cursor from a prior call (10-minute TTL). Cannot be combined with new filters. |
| `limit` | int | no | Max findings per page. Default 0 (summary-first response with `next_cursor`); follow the cursor for more. |
| `min_severity` | string | no | One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Setting this forces the flat response shape. |
| `rule_filter` | string | no | Restrict to specific rule IDs (comma list or `/regex/`). Setting this forces the flat response shape. |

## Invocation

In Claude Code or Cursor:

> Run check_payment_page_scripts on /Users/me/payments-service.

For only the high-impact payment-page rules:

> Run check_payment_page_scripts on /Users/me/payments-service with rule_filter=NONCE-MISSING-PAYMENT,SRI-MISSING-PAYMENT.

## Rule IDs emitted

- `CSP-MISSING` - No Content-Security-Policy header set on the response
- `CSP-UNSAFE-INLINE` - CSP includes `'unsafe-inline'`
- `CSP-UNSAFE-EVAL` - CSP includes `'unsafe-eval'`
- `CSP-NO-SCRIPT-SRC` - CSP missing `script-src` (and no `default-src` fallback)
- `CSP-VALUE-UNANALYZABLE` - CSP value built from a non-literal; static analysis cannot verify correctness
- `CSP-OK` - CSP present with strict directives (informational positive)
- `SRI-MISSING` - External script tag without `integrity` attribute
- `SRI-MISSING-PAYMENT` - External script tag on a payment page without `integrity` (escalated)
- `NONCE-MISSING` - Inline script without `nonce` attribute
- `NONCE-MISSING-PAYMENT` - Inline script on a payment page without `nonce` (escalated)
- `META-CSP-UNSAFE` - `<meta http-equiv="Content-Security-Policy">` with unsafe directives
- `META-CSP-ONLY` - CSP set only via meta tag (HTTP header is required by 6.4.3)
- `FIM-REQUIRED` - File integrity monitoring required for the payment page; not statically verifiable

See [docs/requirement-mapping.md](requirement-mapping.md) for the canonical rule ID to PCI DSS requirement ID mapping.

## PCI DSS requirements covered

- `6.4.3` - Payment page script inventory and integrity controls (CSP, SRI, nonce)
- `11.6.1` - Change/tamper detection on consumer-facing payment pages (FIM)

See [docs/pci-coverage.md](pci-coverage.md) for the full coverage matrix.

## Live findings reference

See live golden output: [`testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`](../testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md). The `CSP-*`, `SRI-*`, `NONCE-*`, `META-*`, and `FIM-*` rule rows begin near `CSP-MISSING` at line 160 of the `## Violations` table and run through `SRI-MISSING-PAYMENT` near line 289.

## Caveats

- The scanner reads both Go HTTP-handler header writes (`w.Header().Set("Content-Security-Policy", ...)`) and HTML template files. Mixed setups with CSP injected by middleware are handled, but very deep template inclusion or runtime header composition may be missed; verify by hand for unusual control flow.
- `CSP-VALUE-UNANALYZABLE` fires when the CSP value is built dynamically (string concat, helper function with non-literal args). Treat as a manual-review prompt, not a clean pass.
- `FIM-REQUIRED` is emitted on every payment page as an advisory; it is not statically verifiable. Pair it with evidence from your deployed FIM tooling (e.g. a SIEM alert rule) when assembling the audit package.
- `SRI-MISSING-PAYMENT` and `NONCE-MISSING-PAYMENT` are the escalated payment-page variants of the generic `SRI-MISSING` / `NONCE-MISSING` rules. Severity is bumped because the page directly handles cardholder data.
- Per `requirement-mapping.md`, `CSP-VALUE-UNANALYZABLE` and `FIM-REQUIRED` carry `partial (static-only, needs QSA)`; the rest are full coverage of their respective 6.4.3 sub-clauses.
