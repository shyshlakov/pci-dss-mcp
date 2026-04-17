# Changelog

All notable changes to pci-dss-mcp are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

## v0.3.2 - 2026-04-17

### Fixed
- Tool descriptions for `triage_findings` and `generate_compliance_report`
  now cross-reference each other so MCP clients can pick the right tool
  for the prompt in one call. `triage_findings` is explicitly flagged as
  the recommended entry point for interactive "scan this project"
  prompts; `generate_compliance_report` is flagged as the plain-report
  alternative for audit artifacts and CI gates. Resolves an observed
  behavior where LLMs double-invoked both tools for "scan, then triage"
  prompts, running the scanner pipeline twice.
- `generate_compliance_report` description now carries the same
  `limit: -1` escape-hatch warning already present on `triage_findings`
  and `scan_pan_data` — symmetrical guidance across all three tools.

### Docs
- README Use Case 2 rewritten as a one-shot `triage_findings` prompt
  with a short note on when to reach for `generate_compliance_report`
  instead.
- `docs/tools.md` sections for both tools now open with tool-selection
  guidance; the legacy-flat-response note for
  `generate_compliance_report` matches the pan/triage variants.

## v0.3.1 - 2026-04-17

### Fixed
- `triage_findings` Layer B default response size on projects with many
  unique rule IDs. The `top_findings` budget now returns 1 enriched
  finding per severity (down from 2) so the serialized response stays
  inside the Claude Code / Claude Desktop inline-render ceiling on
  larger projects. `scan_pan_data` top-N remains 3 per severity.
- `by_rule` histogram in both `triage_findings` and `scan_pan_data`
  Layer B responses is now capped at the 10 highest-count rules. When
  more than 10 rules fire, the omitted count surfaces as `more_rules:
  N` on `summary`. Deterministic ordering (count desc, rule_id asc)
  within the retained 10 is preserved.

### Docs
- `triage_findings` and `scan_pan_data` tool descriptions now open with
  a summary-first framing and flag `limit: -1` as an advanced escape
  hatch that can return >100 KB of JSON. `docs/tools.md` Pagination
  subsections carry the same preamble plus a one-line note about the
  `by_rule` top-10 cap and `more_rules` counter.

## v0.3.0 - 2026-04-17

### Breaking Changes
- `triage_findings` default response shape is now a summary-first variant
  (`response_shape: "summary"`). Previously, unfiltered calls returned a flat
  `TriageResult` with up to 60 enriched findings. The new default response
  carries severity totals, a per-rule histogram, up to 2 enriched findings
  per severity (CRITICAL / HIGH / MEDIUM / LOW / INFO), and a
  `pagination.next_cursor` that the client uses to drill down into the full
  enriched list.

  **Before (v0.2.0):** unfiltered `triage_findings` default response
  ```json
  {
    "findings": [
      {"finding": {...}, "context": {...}, "triage_hint": "..."},
      "... up to 60 enriched findings inline (~85 KB on a ~73-finding project) ..."
    ],
    "metadata": {"findings_total": 73, "findings_triaged": 71, "duration_ms": 2183, "files_analyzed": 41},
    "next_cursor": "eyJzaWQiOiI..."
  }
  ```

  **After (v0.3.0):** same call, default response
  ```json
  {
    "response_shape": "summary",
    "metadata": {"findings_total": 73, "findings_triaged": 71, "duration_ms": 2183, "files_analyzed": 41},
    "summary": {
      "by_severity": {"critical": 1, "high": 13, "medium": 30, "low": 0, "info": 29},
      "by_rule": [
        {"rule_id": "RET-CONFIG-NO-TTL", "count": 18},
        {"rule_id": "AUTH-MISSING-MFA", "count": 9}
      ]
    },
    "top_findings": {
      "critical": ["... up to 2 enriched findings ..."],
      "high":     ["... up to 2 ..."],
      "medium":   ["... up to 2 ..."],
      "low":      [],
      "info":     ["... up to 2 ..."]
    },
    "pagination": {
      "total_findings": 73,
      "returned": 8,
      "next_cursor": "eyJzaWQiOiI...",
      "hint": "Call again with cursor to page through full enriched findings, or use min_severity / rule_filter to narrow."
    }
  }
  ```

- `scan_pan_data` default response shape is now a summary-first variant
  (`response_shape: "summary"`). Previously, unfiltered calls returned a flat
  `ScannerToolOutput` with all findings inline (paginated only when > 60 total).
  The new default response carries severity totals, a per-rule histogram, up
  to 3 findings per severity, and a `pagination.next_cursor` for drill-down.

  **Before (v0.2.0):** unfiltered `scan_pan_data` default response
  ```json
  {
    "scanner": "pan_data",
    "findings": ["... all PAN findings inline ..."],
    "severity_stats": {"critical": 1, "high": 11, "medium": 15, "low": 0, "info": 12},
    "metadata": {"scanned_files": 72, "scanned_lines": 5600, "duration_ms": 890}
  }
  ```

  **After (v0.3.0):** same call, default response
  ```json
  {
    "response_shape": "summary",
    "scanner": "pan_data",
    "metadata": {"scanned_files": 72, "scanned_lines": 5600, "duration_ms": 890},
    "summary": {
      "by_severity": {"critical": 1, "high": 11, "medium": 15, "low": 0, "info": 12},
      "by_rule": [
        {"rule_id": "PAN-KEYWORD", "count": 23},
        {"rule_id": "PAN-TYPE", "count": 8},
        {"rule_id": "PAN-LITERAL", "count": 6},
        {"rule_id": "PAN-LOGGER", "count": 1},
        {"rule_id": "PAN-ZEROING", "count": 1}
      ]
    },
    "top_findings": {
      "critical": ["... up to 3 findings ..."],
      "high":     ["... up to 3 ..."],
      "medium":   ["... up to 3 ..."],
      "low":      [],
      "info":     ["... up to 3 ..."]
    },
    "pagination": {
      "total_findings": 39,
      "returned": 12,
      "next_cursor": "eyJzaWQiOiI...",
      "hint": "Call again with cursor to page through full findings, or use include_tests / exclude_patterns to narrow scope."
    }
  }
  ```

- **Migration.** Pass `limit=-1` on the next call to `triage_findings` or
  `scan_pan_data` to restore the pre-v0.3.0 flat response shape (auto-capped
  at 500 findings). Alternatively, follow the `pagination.next_cursor` to page
  through findings 60 at a time. Passing any of `min_severity`, `rule_filter`,
  or (for `scan_pan_data`) `exclude_patterns` / `include_tests` /
  `include_untracked` / `include_taint` also continues to return the flat
  shape with pagination support.

- `triage_findings` and `scan_pan_data` responses now include a
  `response_shape` discriminator field at the top level of `StructuredContent`.
  Valid values: `"summary"` (Layer B), `"flat"` (Layer A / Layer C), `"error"`
  (cursor error variants). Clients that dispatch on this field should handle
  all three.

- `scanner.ScannerToolOutput` (shared typed output for every single-scanner
  tool) grew a `response_shape` field set to `"flat"` by `BuildScannerToolOutput`.
  Downstream callers that unmarshal `ScannerToolOutput` must tolerate the extra
  field; callers that pin the full struct shape in a test snapshot should
  update their fixtures.

### Added
- Three-layer hybrid response dispatcher for `triage_findings` and
  `scan_pan_data`:
  - **Layer B -- summary-first.** Default for unfiltered, cursor-less calls.
  - **Layer A -- cursor pagination.** Triggered on cursor resume OR when any
    filter / scope input is set.
  - **Layer C -- auto-cap safety net.** Triggered only on explicit `limit=-1`.
- `triage_findings` summary response: top-N = 2 enriched findings per severity
  bucket (max 10 enriched inline). Empty severity buckets ship as `[]`.
- `scan_pan_data` summary response: top-N = 3 findings per severity bucket
  (max 15 inline). Empty severity buckets ship as `[]`.
- Both tools declare `_meta.anthropic/maxResultSizeChars: 20000` so MCP
  clients supporting the annotation (e.g. Claude Code) know the soft
  character ceiling in advance.
- Both tools' `OutputSchema` is a `oneOf` union of three variants
  (`*SummaryResponse`, flat response, `*CursorError`) with a `response_shape`
  const discriminator per variant.
- Cross-tool cursor guard: a cursor issued by `triage_findings` is rejected
  by `scan_pan_data` and vice versa with a structured `CURSOR_MALFORMED`
  error. Already enforced for `generate_compliance_report` as of v0.2.0.

### Internal
- New `scanner/hybrid/` package exposing a generic
  `SelectAndExecute[TFinding, TSummary, TFlat any]` selector with injected
  `Scan`, `Filter`, `BuildSummary`, `BuildFlat`, `Cacher[TFinding]` callbacks.
  Shared by both single-scanner tools migrated in this release; reportscanner
  keeps its private `SelectAndExecute` as-is (migration is optional and
  deferred). Import graph stays acyclic:
  `scanner/hybrid -> scanner/hybridcache -> scanner`.
- `scanner/triagescanner/summary.go` -- new `TriageSummaryResponse` +
  `buildTriageSummaryInternal` + `pickTopNTriage` with deterministic
  severity -> rule_id -> file_path ordering.
- `scanner/panscanner/summary.go` -- new `PANSummaryResponse` +
  `buildPANSummaryInternal` + `pickTopNPAN` with the same deterministic
  ordering.
- `scanner/triagescanner/output_schema.go` + `scanner/panscanner/output_schema.go`
  -- `oneOf` union schema builders mirroring the v0.2.0
  `scanner/reportscanner/output_schema.go` pattern.
- `scanner/tooloutput.go` -- `ScannerToolOutput` grows a `ResponseShape`
  field set to `"flat"` by `BuildScannerToolOutput` so the union schema
  validates a discriminator at the top level.
- New cross-tool integration test in `scanner/hybrid/layerb_crosstool_test.go`
  -- spins up both tools through an in-memory MCP transport and asserts
  both Layer B wire sizes stay under 20480 bytes on the golden fixture.
- New smoke script at `scripts/pci-layerb-smoke.go` (`go run -tags smoke`)
  measures Layer B wire size via an in-memory MCP transport for
  operator-driven UAT on any target path.

### Docs
- `docs/tools.md` updated with a v0.3.0 migration note and per-tool
  Pagination and cursor subsections for `triage_findings` and `scan_pan_data`
  mirroring the v0.2.0 pattern for `generate_compliance_report`.

### Known limitations
- `anthropic/maxResultSizeChars` is currently honoured by Claude Code
  (verified against v2.1.91, April 2026). Claude Desktop and Cursor
  treatment is undocumented; the 20000 declaration is intended as an
  informational hint for any client that recognises the `_meta` key.
- Claude Desktop's exact 2026 character ceiling remains unconfirmed; top-N
  caps (2 / 3) target a conservative 20K binding so Layer B fits within any
  plausible client display window.
- `generate_compliance_report` continues to use its private
  `SelectAndExecute` in `scanner/reportscanner/`. Migration to the shared
  `scanner/hybrid/` helper is a nice-to-have deferred to a follow-up phase;
  behaviour is unchanged.

### Metrics
- `triage_findings` Layer B wire size on the golden fixture:
  **under the 20480-byte budget with headroom** (see
  `scanner/triagescanner/layerb_test.go:TestTriageLayerB_SizeBudget20KB`).
- `scan_pan_data` Layer B wire size on the golden fixture:
  **under the 20480-byte budget with headroom** (see
  `scanner/panscanner/layerb_test.go:TestPANLayerB_SizeBudget20KB`).
- Live-path UAT on a real-world Go payment service workload (~50+ active
  findings): both tools render inline in Claude Code; no "read in chunks"
  fallback banner. Pre-v0.3.0 reference for the same workload:
  `triage_findings` returned ~85 KB and triggered chunked-read mode.
- Golden fixture `make test-fixture` severity counts unchanged
  (CRITICAL=49 HIGH=89 MEDIUM=27 LOW=0 INFO=59) -- this release adds no
  detection logic, only reshapes how findings are wrapped on the wire.

## v0.2.0 - 2026-04-17

### Breaking Changes
- `generate_compliance_report` default response shape is now a summary-first
  variant (`response_shape: "summary"`). Previously, unfiltered calls returned
  a flat `findings: [...]` array wrapped in a `ComplianceReport` envelope.
  The new default response carries severity totals, per-requirement statuses,
  up to 10 top findings per severity, and a `pagination.next_cursor` that the
  client uses to drill down into the full findings list.

  **Before (v0.1.5):** unfiltered `generate_compliance_report` default response
  ```json
  {
    "metadata": {"target_path": "...", "duration_ms": 1210, "total_files": 72},
    "summary": {"critical": 49, "high": 89, "medium": 27, "low": 0, "info": 59},
    "findings": [
      {"rule_id": "PAN-KEYWORD", "severity": "HIGH", "file_path": "...", ...},
      "... all 178 active findings inline ..."
    ],
    "requirement_status": [...14 entries + 213 NOT_CHECKED...],
    "compliance_status": "FAIL",
    "active_findings": 178
  }
  ```

  **After (v0.2.0):** same call, default response
  ```json
  {
    "response_shape": "summary",
    "metadata": {"target_path": "...", "duration_ms": 1210, "total_files": 72},
    "summary": {"critical": 49, "high": 89, "medium": 27, "low": 0, "info": 59},
    "requirement_statuses": [...14 entries; NOT_CHECKED filtered out...],
    "top_findings": {
      "critical": ["...up to 10 findings (stripped code_snippet / fix_hint)..."],
      "high":     ["...up to 10..."],
      "medium":   ["...up to 10..."]
    },
    "pagination": {
      "total_findings": 178,
      "returned": 30,
      "next_cursor": "eyJzaWQiOiI...",
      "hint": "call generate_compliance_report with cursor for the full flat page; pass limit=-1 to get legacy flat shape (capped at 500)",
      "auto_capped": false
    }
  }
  ```

- **Migration.** Pass `limit=-1` on the next call to `generate_compliance_report`
  to restore the pre-v0.2.0 flat findings array (capped at 500 by safety net).
  Alternatively, follow the `pagination.next_cursor` to page through findings
  60 at a time.

- New `cursor` input parameter on `generate_compliance_report`, `triage_findings`,
  and `scan_pan_data`. Empty string or absent = fresh scan. Non-empty = resume
  from server-side session cache (10-minute TTL). Cursors are tool-scoped;
  reusing a `generate_compliance_report` cursor on `triage_findings` (or vice
  versa) returns a `CURSOR_MALFORMED` error.

- New error responses: clients must handle the structured error shape.
  - `CURSOR_EXPIRED` — session cache entry expired (10-minute TTL) or server
    restarted. Hint: re-run without cursor to start a fresh scan.
  - `CURSOR_MALFORMED` — cursor failed to decode, or its embedded tool name
    does not match the current tool.

### Added
- Three-layer hybrid response dispatcher for `generate_compliance_report`
  (F-29, implemented via `SelectAndExecute`):
  - **Layer B — summary-first.** Triggered on unfiltered calls
    (`limit == 0 && min_severity == "" && rule_filter == "" && cursor == ""`).
    Returns `SummaryResponse`: severity totals, requirement statuses,
    up to 10 top findings per severity (CRITICAL / HIGH / MEDIUM),
    `pagination.next_cursor` set for drill-down.
  - **Layer A — cursor pagination.** Triggered when a cursor is present OR
    any filter is set (`rule_filter`, `min_severity`, positive `limit`).
    Returns `FlatResponse` with 60 findings per page plus `next_cursor`
    when more pages remain.
  - **Layer C — auto-cap safety net.** Triggered ONLY by explicit `limit=-1`.
    Returns a flat `findings` array; if size exceeds 500 the response is
    capped with `pagination.auto_capped: true, total_before_cap, kept, hint`.
- `cursor` input parameter on `generate_compliance_report`, `triage_findings`,
  `scan_pan_data`.
- `OutputSchema` for `generate_compliance_report` is now a `oneOf` union of
  `SummaryResponse`, `FlatResponse`, and `CursorExpiredError` variants with
  a required `response_shape` const discriminator (`"summary"`, `"flat"`,
  `"error"`).
- Session caches for cursor-paginated follow-up — in-memory `sync.Map`,
  10-minute TTL, 60-second lazy eviction sweep via background ticker. Each
  tool owns a typed cache: `generate_compliance_report` stores
  `[]ReportFinding` in `scanner/reportscanner`; `scan_pan_data` and
  `triage_findings` share `[]scanner.Finding` via `scanner/hybridcache`.
  Both caches follow the same TTL, eviction, and fake-clock test contract.

### Internal
- New `scanner/reportscanner/session.go` — package-level `sync.Map`, injected
  `Clock` interface, `sync.Once`-gated background evictor. Mirrors the
  `internal/taint/engine.go` session-cache pattern.
- New `scanner/reportscanner/cursor.go` — opaque `base64.RawURLEncoding` JSON
  cursor (`{sid, off, tool}`) with cross-tool namespace guard.
- New `scanner/reportscanner/hybrid.go` — D-01 layer selector
  `SelectAndExecute`; Layer A/B/C builders `buildSummary`,
  `buildFlatPage`, `buildAutoCapFlat`; top-finding stripping
  (`stripSummaryFindings` drops `code_snippet` / `fix_hint` /
  `related_requirements` for the summary panel).
- New `scanner/reportscanner/output_schema.go` — `buildOutputSchemaUnion`
  + `pinResponseShape` helper that overrides the inferred property's
  `const` field per variant (jsonschema-go has no const struct tag).
- New `scanner/hybridcache/hybridcache.go` — cross-package cursor + session
  cache for the single-scanner tools (`scan_pan_data`, `triage_findings`).
  Introduced to break the `reportscanner ↔ panscanner` import cycle that
  would otherwise arise from sharing reportscanner's Wave 1 primitives
  with the two single-scanner tools. `generate_compliance_report` keeps
  its own typed cache in `scanner/reportscanner/session.go` because the
  payload type (`[]ReportFinding`) diverges from the shared cache's
  `[]scanner.Finding` shape.
- New `scanner/reportscanner/format_stability_test.go` +
  `scanner/reportscanner/testdata/format_golden.txt` — byte-identical CLI
  output regression guard. `FormatHumanReadable` is unchanged by this
  release and must remain unchanged going forward.
- Extended `scanner/tool_output_schema_test.go` with
  `TestOutputSchema_GenerateReport_HasOneOfUnion` — walks registered
  tools, asserts the union is declared with exactly three variants.
- `scanner/tooloutput.go`: `ScannerToolOutput` grows `TotalFindings` and
  `NextCursor` fields so single-scanner tools can paginate through the
  `hybridcache` session store.
- `scanner/triagescanner/types.go`: `TriageResult` grows a `NextCursor`
  field (omitempty) for paginated responses.

### Docs
- `docs/tools.md` updated with a top-of-file v0.2.0 migration note and
  per-tool "Pagination and cursor" subsections for
  `generate_compliance_report`, `triage_findings`, and `scan_pan_data`.

### Known limitations
- Persistent disk cache is deferred (tracked as backlog item F-30).
  Process restart invalidates all outstanding cursors; clients see
  `CURSOR_EXPIRED` and must re-run without a cursor.
- HMAC-signed cursors are an optional defense-in-depth item; this release
  ships opaque-but-unsigned cursors. The threat surface is a
  single-process stdio MCP server, which is low exposure.
- `chi`-style inline middleware (`r.With(...).Post(...)`) is not yet
  recognised by the shared hybrid middleware crawler; use route-group
  registration via `r.Use(...)` to remain detectable.

### Metrics
- Layer B response size on the golden fixture: **19,986 bytes** (budget
  25,600). `TestLayerB_FixtureBudget25KB` locks this invariant.
- Golden fixture `make test-fixture` counts unchanged
  (CRITICAL=49 HIGH=89 MEDIUM=27 LOW=0 INFO=59) — this release adds no
  detection logic, only reshapes how findings are wrapped on the wire.

## v0.1.5 - 2026-04-17

### Fixed
- `AUTH-MISSING-MFA` downgrades to INFO on service-to-service / webhook handlers via consensus multi-signal classifier. Strong T1 signals include `hmac.Equal`, `subtle.ConstantTimeCompare`, `rsa.Verify*`, `ecdsa.Verify*`, `ed25519.Verify`, `jwt.Parse`/`ParseWithClaims`, `jose.ParseSigned`, brand-SDK calls (`webhook.ConstructEvent`, `hmacvalidator.ValidateHmac*`, `client.VerifyWebhookSignature`). Medium T2 signals are handler-name regex match plus webhook route path plus POST/PUT method. Weak T3 signals are absence of Authorization header read and the raw-body-then-parse pattern. Rule: `is_s2s = strong >= 1 OR (medium >= 2 AND weak >= 1)`. Negative kill-switch: any of `session.Save`/`session.Set`, gin `c.SetCookie` 7-arg, stdlib `http.SetCookie` 2-arg, or raw `w.Header().Set("Set-Cookie", ...)` keeps the finding at HIGH (OAuth callback recall guard). Downgraded findings carry TriageHint `downgrade:s2s_handler | <signal reason>` and add PCI DSS 8.6.1 + 8.6.2 to RelatedRequirements (machine-auth context per PCI 8.4.2 Applicability Notes). Eliminates ~75% of HIGH AUTH-MISSING-MFA false positives observed on real-world payment microservices.

### Added
- New detection rule `AUTH-WEBHOOK-NO-SIGNATURE` for webhook handlers parsing request payloads without prior signature verification. Severity is `CRITICAL` when the route path contains a payment brand keyword (`stripe`, `adyen`, `mdes`, `mastercard`, `paypal`, `visa`, `cybersource`, `apple-pay`, `applepay`, `google-pay`, `googlepay`, `checkout`, `worldpay`, `square`, `braintree`, `fiserv`) and `HIGH` for generic webhook paths. Maps to PCI DSS 6.2.4 (input validation); brand-path findings additionally cite 4.2.1 (CHD transmission authentication).
- New `AUTH-WEBHOOK-VERIFIED` verified-OK INFO marker. Emitted when a handler verifies the webhook signature via T1 strong selectors (`hmac.Equal`, `subtle.ConstantTimeCompare`, `rsa.Verify*`, `ecdsa.Verify*`, `ed25519.Verify`, `jwt.Parse`, `jose.ParseSigned`, brand SDKs `webhook.ConstructEvent` / `hmacvalidator.ValidateHmac*` / `client.VerifyWebhookSignature`) BEFORE the first body-parser call (`token.Pos` ordering), or via a 1-level local helper recursion (`verify*` / `validate*` / `authenticate*` / `check*Sig*` named helpers, cycle-guarded), or via a route-middleware chain containing `VerifyHMAC` / `VerifyWebhookSignature` / `WebhookAuth`-shaped wrappers. TriageHint `webhook_signature_verified | <hit>`. Auto-skipped by the triage engine via the existing `HasSuffix("-VERIFIED")` rule.

### Internal
- New `scanner/authscanner/s2s_handler.go` — per-file fixup wired into `authscanner.scanGoFileInRoot` immediately after `detectMissingMFA`. Mirrors `sqlscanner.applyVerifiedTypeFixup` architecture.
- New `scanner/authscanner/webhook_signature.go` — `WebhookSignatureScan` tracks first body-parser call via `token.Pos`, checks for signature-verify signals strictly before the parser, supports 1-level cycle-guarded helper recursion, and applies brand-path segment scoping (brand keyword must appear after `/webhooks/`, `/callbacks/`, `/notifications/`, `/hooks/`, `/cb/`, `/ipn/`, or `/events/`).
- New `scanner/authscanner/webhookmiddleware.go` — forked from `scanner/auditscanner/pkgmiddleware.go` (~420 LOC; Pass A + parent-walk; `InstallRoutes` Pass B intentionally dropped for this release). Predicate substituted from `argLooksLikeLogger` to `argLooksLikeSignatureMiddleware` (regex `(?i)(hmac|signature|webhook|verify|auth)`). Independent cache `webhookCachePackages` reset per scan via `ResetWebhookMiddlewareCache()` invoked at top of `authscanner.ScanFull` (mirroring `auditscanner.ResetPackageCache()` arrangement; reportscanner is unchanged).
- 2 clean fixture files under `testdata/vulnerable-payment-service/clean/s2s_handler/` covering T1-strong (HMAC verification before parse) and T2+T3 consensus.
- 1 adversarial fixture `testdata/vulnerable-payment-service/internal/http/handler/admin/admin_panel.go` locks the D-03 negative-signal rule (handler with webhook-shaped name but Set-Cookie write stays HIGH).
- 3 bad webhook fixtures under `testdata/vulnerable-payment-service/internal/http/handler/webhook/` (`bad_stripe_webhook.go`, `bad_generic_webhook.go`, `bad_paypal_ipn.go`) that fire `AUTH-WEBHOOK-NO-SIGNATURE` at CRITICAL/HIGH severities per D-05.
- 4 good webhook fixtures under `testdata/vulnerable-payment-service/clean/webhook_signed/` (`good_stripe_constructevent.go`, `good_hmac_generic.go`, `good_middleware_verified.go`, `webhook_with_local_helper.go`) that emit `AUTH-WEBHOOK-VERIFIED` INFO.
- Existing `testdata/vulnerable-payment-service/internal/http/handler/callback/mastercard.go` now also fires `AUTH-WEBHOOK-NO-SIGNATURE` CRITICAL alongside its existing `AUTH-MISSING-MFA` finding (real Mastercard card-update callback canonical anti-pattern).
- Triage output budget bumped from 184 KB to 240 KB to accommodate the additional webhook-related findings and their triage context payloads.

### Known limitations
- chi-style inline middleware `r.With(VerifyMW).Post(...)` is NOT detected by this release's webhookmiddleware crawler. Use `r.Use(VerifyMW)` group registration to be detected.
- PayPal `VerifyWebhookSignature` is treated as a T1 strong signal even though it is a network call to PayPal (not a local crypto check). Real-world handlers using this pattern are generally safe; offline test environments will not exercise this path.
- Replay-attack timestamp checks (`Stripe-Signature` `t=` tolerance enforcement) are out of this release's scope.

## v0.1.4 — 2026-04-16

### Fixed
- **F-26** GORM encrypted custom type verification. Recognizes the modern GORM encryption-at-rest pattern where a custom Go type implements `driver.Valuer` with transparent column encryption via the `Value()` (or `GormValue()`) method body. The sqlscanner now AST-walks each candidate body for real cryptographic primitive calls before emitting `GORM-NO-ENCRYPT-HOOK`. Recognized strong signals include `aes.NewCipher`, `cipher.NewGCM`, `cipher.NewCBCEncrypter`, `crypto/rand.Read`, `crypto/hmac.New`, `golang.org/x/crypto/nacl/secretbox.Seal`, `golang.org/x/crypto/chacha20poly1305.New`, and `github.com/google/tink/go/aead.Encrypt`. A KMS-client heuristic accepts any method in `{Encrypt, EncryptCtx, EncryptWithContext, Seal, Wrap}` invoked on a receiver whose name contains `kms`, `vault`, `hsm`, `barbican`, `secretmanager`, or `keymanager`. One level of intra-package helper recursion is followed with a cycle guard. Reduces false positives by 2-3 per service on real-world payment codebases that use custom encrypted column types.

### Added
- New `GORM-ENCRYPT-OK` INFO marker (follows the `-OK` suffix convention from `AUDIT-LOG-OK` / `CSP-OK`). Emitted when a struct field's custom type has a verified-encrypted `Value()` method. The triage engine auto-skips it via the existing `HasSuffix("-OK")` rule.
- Sibling `GORM-SENSITIVE-TAG` findings on the same field drop to INFO with a matching triage hint when the field type passes verification.

### Internal
- New `scanner/sqlscanner/valuerscan.go` with `verifyValueBody`, `buildVerifiedTypeMap`, `collectPkgFuncEntries`, the D-02 strong-signal whitelist, the D-03 KMS receiver/method heuristic, and the D-04 1-level recursion with cycle guard.
- `scanner/sqlscanner/sqlscanner.go` Pass 2 now also accumulates verified custom-type entries and package-level helper functions across the whole module walk; a new Pass 2b applies the verified-type fixup to `GORM-NO-ENCRYPT-HOOK` and `GORM-SENSITIVE-TAG` findings before SQL cross-reference. Per-file imports travel with each helper so cross-file recursion resolves alias paths correctly.
- 7 new clean fixture files under `testdata/vulnerable-payment-service/clean/gorm_encrypt_type/` covering direct-crypto, helper-recursion, and KMS-client patterns. 1 adversarial type fixture (`internal/crypto/fake_encrypted_string.go`, base64-only `Value()`) and 1 adversarial GORM model fixture (`internal/storage/postgres/model/fake_encrypt_model.go`) lock the D-06 NOT-signal rejection rule.
- Triage output budget bumped from 160 KB to 176 KB to accommodate the two additional active findings on the adversarial fixture.

## v0.1.3 — 2026-04-16

### Fixed
- **F-25** Five-layer CRYPTO-HARDCODED-KEY filter cascade reduces false positives on HTTP header constants, sentinel errors, log field names, JSON key names, and constants files. Layer 1 (AST sentinel error guard), Layer 2 (shape heuristics with Shannon entropy guard), Layer 3 (hex/base64 fast-path forces CRITICAL on genuine keys), Layer 4 (path downgrade for constants/errors files). All downgraded findings carry TriageHint tags for auditor visibility.
- **F-27** IBAN vs PAN sibling heuristic for banking-domain structs. AccountNumber fields in structs with >= 2 banking siblings (IBAN, BIC, SWIFT, RoutingNumber, SortCode, ABA, BankCode) and zero PCI-scope siblings downgrade PAN-KEYWORD to INFO. Defense-in-depth guards: any PCI-scope sibling, card-related struct tags, or tokenization context aborts the downgrade.

### Changed
- README Use Cases section: updated quick-scan prompt to include INFO findings review instead of discarding them. Added "Why INFO findings matter" section explaining the audit trail design for developers, auditors, and CI pipelines.

### Internal
- New `scanner/cryptoscanner/hardcoded_filter.go` with `ApplyHardcodedFilter` five-layer cascade.
- New `scanner/panscanner/banking_context.go` with `IsBankingContext` sibling analysis.
- 8 new fixture files in `testdata/vulnerable-payment-service/` covering all filter layers and banking context patterns.
- Fixed 6 missing CSP-MISSING INFO entries and 3 stale line numbers in EXPECTED-FINDINGS.md (pre-existing path-dependency gap, not a Phase 19.7 regression).

## v0.1.2 — 2026-04-15

### Fixed
- **F-24** `scanner/devcontext.go` now recognizes `examples/`, `example/`, `samples/`, `sample/` directory segments and `config.example.*`/`config.sample.*` filename patterns as dedicated dev-context. Credential findings inside these paths downgrade from CRITICAL to INFO and carry `TriageHint: dev_path_examples_skipped` for auditor visibility. Preserves recall via `configs/prod-*` adversarial fixture that stays CRITICAL.
- **F-28** `scanner/walker.go` and `scanner/gitwalker.go` now skip files whose project-relative path contains a case-sensitive segment in `{test, testing, mocks, fixtures, e2e}` when `IncludeTests=false`, beyond the existing `*_test.go` suffix check. `testdata` (golden fixture tree) and `integration` (production payment integration directories like `internal/integration/stripe/`) are deliberately excluded from the set for recall safety. Real-world impact: ~5 false positives removed on a production payment-service scan.

### Internal
- New `scanner/pathsegments.go` with shared `hasTestDirSegment(root, path) bool` helper used by both walkers.
- Fixture rename `testdata/vulnerable-payment-service/internal/test/` to `internal/testseed/` to avoid collision with the new walker exclusion rule. No behavioural change for the fixture acceptance test.
- New `scanner.DevContext.ExamplesPath bool` field to let callers distinguish examples-dev from generic-dev paths.

## [0.1.1] - 2026-04-15

False-positive reduction for three scanners plus a latent alignment bug
in the SQL cross-reference pass. No new MCP tools or rules; existing
scan output is more precise on real-world Go payment-service codebases.

### Changed
- **retentionscanner: `RET-CONFIG-NO-TTL` path-aware downgrade.** Findings
  under directory segments matching `dev`, `local`, `compose`, `testutil`,
  `testutils`, or `test` (with sub-word split on `_`/`-`) downgrade to
  `INFO` with TriageHint `downgrade:dev_path_skipped | ...`. Production
  paths under `configs/` and equivalent keep their original HIGH severity.
  Eliminates ~20 false positives per scan on typical monorepo
  dev-infrastructure compose files.
- **sqlscanner: temporal DROP COLUMN awareness.** A new Pass 4 walks
  migration files in chronological order inside `migrations/` and
  `migration/` directories. When a later migration contains
  `DROP COLUMN <col>` (with optional `IF EXISTS`) for a flagged column
  and no subsequent migration re-adds it, `SQL-SENSITIVE-COLUMN` and
  `SQL-TEXT-TYPE` findings for the add-migration downgrade to `INFO`
  with TriageHint `downgrade:column_dropped_in_<file> | ...`. Re-ADD
  detected via `ALTER TABLE ... ADD COLUMN <col>` → severity preserved.
  Heuristic aborts for a directory if any file lacks a timestamp prefix.
- **authscanner: testutil path exclusion extended.** `AUTH-HARDCODED-PWD`
  findings under paths containing a segment equal to `test`, `testutil`,
  or `testutils` (including `internal/testutil/**`, `internal/testutils/**`,
  and `**/test/**`) downgrade to `INFO` with TriageHint
  `downgrade:testutil_exclusion | ...`. Findings are never dropped —
  the audit trail is preserved per the D-01 binding rule.
- **README: Roadmap section added** listing five upcoming user-facing
  features (SBOM generation, govulncheck reachability, SARIF v2.1.0
  output, Semgrep adapter, cross-service CHD flow mapping). Stale
  `RET-CONFIG-NO-TTL over-firing` note removed from Known limitations.

### Fixed
- **sqlscanner: `crossRefSQLWithGoEncryption` / `applyMigrationDropDowngrade`
  alignment bug.** When the cross-reference pass suppressed an expiry
  column under a Go-level PAN encryption hook, it deleted findings via
  slice `append` but left `sqlFindingEnd` and `sqlMetas` pointing at the
  pre-deletion state. The subsequent migration-drop pass then iterated
  with a stale 1:1 finding↔meta alignment and could pair a SQL finding
  with the wrong column meta — in the worst case leaving a sensitive
  column (e.g. CVV) dropped in a later migration at HIGH instead of
  INFO. `crossRefSQLWithGoEncryption` now returns updated findings,
  `sqlMetas`, and `sqlEnd`; the suppression loop prunes both slices in
  lockstep in reverse order. Regression covered by
  `TestScanFullMigrationDropAfterCrossRefSuppression`.

### Metrics
- Real-world smoke scan on a production payment service: MEDIUM+ finding
  count dropped from 110 to 76 (−34 findings, 30.9% reduction). Both
  OpenTelemetry CVEs (`GHSA-9h8m-3fm2-qjrq`, `GHSA-hfvc-g4fc-pqhx`)
  still detected at HIGH on `go.opentelemetry.io/otel/sdk@v1.39.0`.
- Regression-check on a second production service baseline: 0 CRITICAL /
  4 HIGH / 3 MEDIUM — byte-for-byte match with the pre-0.1.1 baseline.
- Golden fixture: all expected counters updated in
  `testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md`;
  `make test-fixture` exits 0 with dual tempdir + LivePath coverage
  for the three new heuristics.

## [0.1.0] - 2026-04-15

First public release. Covers the complete PCI DSS v4.0.1 scanner suite as a
Model Context Protocol server for Go payment-service codebases.

### Security
- No known run-time vulnerabilities fixed in this release. `govulncheck` is
  clean against the dependency set at the time of release.

### Added
- **14 MCP tools** across 10 scanners covering PCI DSS v4.0.1 requirements
  3.2.1, 3.3.1, 3.4.1, 3.5.1, 4.2.1, 6.2.4, 6.3.3, 6.4.3, 8.3.1, 8.3.6,
  8.4.2, 8.6.2, 10.2.1, and 11.6.1.
- **Compliance orchestrator** (`generate_compliance_report`) that runs every
  scanner and returns a typed, per-requirement PASS / FAIL / NOT_CHECKED
  report with finding-level `requirement_id` mapping.
- **Triage engine** (`triage_findings`) that enriches active findings with
  on-demand `ResourceLink` hints (per MCP spec 2025-06-18 `resource_link`
  content type), imports, middleware chain, and triage hints. Clients read
  source from the hinted files using their own `Read` tool rather than
  receiving inline source bytes.
- **Taint-aware severity adjustment** in the PAN scanner via a type-aware
  data-flow engine built on `golang.org/x/tools/go/packages`. Implements
  the PCI SSC FAQ on non-persistent memory: transit-only CHD in request
  DTOs is downgraded to INFO (or suppressed entirely for `PAN-TYPE`), while
  CHD that flows to storage sinks keeps HIGH severity.
- **Multi-signal payment-context scorer** (`PaymentContextScore` /
  `IsPaymentContext`) that classifies functions as payment-related based on
  keyword, package path, import, and tag signals rather than a single
  keyword gate.
- **Audit log field verification** for the four popular Go logger APIs
  (logrus, slog, zap, zerolog). Parses middleware bodies, resolves field
  name constants from cross-package imports, and scores handler coverage
  of the five PCI DSS 10.2.1 categories (timestamp, event type, user
  identification, outcome, affected resource).
- **Cross-file middleware detection** that walks parent package directories
  to find logging middleware registered outside the handler's own package,
  resolving method values like `r.Use(m.requestLogger)` by following
  the receiver type.
- **Dependency vulnerability scanning** via the OSV.dev advisory database
  with an offline-capable local cache (`update_vulnerability_db` refreshes
  the cache for air-gapped CI environments).
- **Delegation-only handler detection** in the MFA scanner — skips
  `AUTH-MISSING-MFA` on single-statement wrapper handlers that only forward
  to another `http.Handler` via `ServeHTTP` / `ServeHTTPC` / gin / echo.
- **Verified-OK markers** (`AUDIT-LOG-OK`, `CSP-OK`) emitted for informational
  visibility in `generate_compliance_report`. The triage engine automatically
  skips markers whose rule ID ends with `-OK` via a simple `HasSuffix` rule.
- **Filter parameters** (`min_severity`, `rule_filter`, `limit`) on
  `generate_compliance_report` and `triage_findings`. Filtering is applied
  before serialization via a shared `FilterFindings` helper so responses
  shrink on noisy projects.
- **Compact JSON output** on every tool — no `json.MarshalIndent`, no
  hybrid text+JSON dual formats. Every tool declares a typed `OutputSchema`
  auto-inferred from the output struct's `jsonschema` tags.
- **Golden vulnerable fixture** at `testdata/vulnerable-payment-service/`
  with a machine-readable `EXPECTED-FINDINGS.md` contract covering every
  production rule plus clean counter-examples.
- **Suppression system** with `pci-ignore` inline comments and a
  `.pci-dss-mcp-ignore` file. Suppressed findings surface as `SUPPRESSED` with
  reason — never silently dropped.
- **Documentation** under `docs/` covering tools reference, severity model,
  taint scoping guidance, CI/CD integration, and PCI DSS coverage map.

### Notes
- pci-dss-mcp is a static analysis tool. It covers approximately 6 percent of
  PCI DSS v4.0.1 requirements (14 of 249). The remaining 94 percent require
  manual review by a Qualified Security Assessor.
- Taint analysis is ON by default. Use `include_taint: false` (or
  `gen.GenerateFast` for library callers) to disable for fast dev iteration
  at the cost of more transit-only false positives.
