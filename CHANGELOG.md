# Changelog

All notable changes to pci-dss-mcp are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

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
