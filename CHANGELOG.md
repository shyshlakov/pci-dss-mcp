# Changelog

All notable changes to pci-dss-mcp are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

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
