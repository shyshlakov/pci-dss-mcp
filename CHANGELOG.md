# Changelog

All notable changes to pci-dss-mcp are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

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
