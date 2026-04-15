# Scoping pci-dss-mcp on mixed-domain projects

pci-dss-mcp uses a **multi-signal payment-context scorer** to decide which
functions should be analyzed for payment-specific compliance rules
(AUDIT-NO-LOG, AUTH-MISSING-MFA, CSP-MISSING, ERR-LEAK-*, RET-ZERO-*). The
scorer is deliberately **recall-biased**: it prefers to emit a finding you
can triage over silently skipping code that might contain a real PCI DSS
violation. On a pure payment service this is exactly what you want. On a
mixed-domain project — a codebase that contains both payment code AND
something the scorer can plausibly confuse with payment code — you will
occasionally see findings on genuinely non-payment packages.

This page explains how to scope pci-dss-mcp down when that happens, without
suppressing individual findings one-by-one.

## The `exclude-package:` directive

Add a `.pci-dss-mcp-ignore` file at your project root with one or more
`exclude-package:` directives. Each directive is a glob pattern against the
package directory relative to the project root. Matching packages are
**short-circuited** — pci-dss-mcp does not parse any files inside them.

**Glob syntax:**

- `**` matches any number of path segments (including zero).
- `*` matches one path segment.
- Prefix match: `internal/game/**` matches `internal/game/`, `internal/game/card/`, etc.
- Patterns are matched against the package directory relative to the project root.

**Audit trail:** every pattern that matches at least one finding produces a
`SUPPRESSED-PACKAGE` INFO entry in the compliance report. QSA auditors see
exactly which packages were scoped out and the count of findings dropped.
Silent scope reduction is not possible.

## Example 1 — Card game with a `/card/` package

A chess/poker/blackjack engine lives at `internal/card/`. The scorer treats
`/card/` as payment context (signal 2, +2) because real payment services use
`/card/` for cardholder data. The solution:

```
# .pci-dss-mcp-ignore
exclude-package: internal/card/**    # card game, not payment cards
exclude-package: pkg/deck/**         # card deck logic, no CHD
```

After this, running pci-dss-mcp on the project produces zero findings inside
`internal/card/` or `pkg/deck/`. The compliance report will include one INFO
entry per matched pattern:

```
SUPPRESSED-PACKAGE  INFO  internal/card/**  Package pattern "internal/card/**" excluded by .pci-dss-mcp-ignore (dropped N findings).
```

## Example 2 — Multi-service monorepo with billing + user profiles

A monorepo contains `services/billing/` (real payment code, in scope) and
`services/user-profile/` (handles user metadata, out of scope). Payment
compliance checks should ONLY cover billing:

```
# .pci-dss-mcp-ignore
exclude-package: services/user-profile/**    # user profiles, no CHD
exclude-package: services/notification/**    # outbound email/sms
exclude-package: services/search/**          # aggregate index, no CHD
```

All payment-context findings inside `services/billing/` continue to fire.
Everything under the excluded service directories is skipped before parsing,
which is also a measurable performance win on large monorepos.

## Example 3 — Shared `pkg/models/` with a `Card` struct

A shared types package at `pkg/models/` defines a `Card` struct used by both
payment services (in scope) AND non-payment services (out of scope). Because
pci-dss-mcp is a static analyzer, it cannot know which consumers are in-scope —
it flags every consumer that imports the package. The fix is to exclude the
non-payment consumers, not the shared types:

```
# .pci-dss-mcp-ignore
# Shared types stay in scope — they are the CDE boundary
exclude-package: services/inventory/**
exclude-package: services/catalog/**
exclude-package: services/analytics/**
```

The shared `pkg/models/` IS in scope — its contents are cardholder data type
definitions, and any consumer that imports them inherits the PCI DSS handling
responsibility. Exclude only the specific consumers you have determined via
architectural review to be out-of-scope (e.g. tokenized-data-only readers).

**Warning:** if any of those excluded consumers actually handle CHD (for
example, an admin dashboard that re-validates plaintext card numbers),
excluding it hides real findings. `exclude-package:` is a scoping tool for
genuinely out-of-scope code, not a suppression tool for inconvenient
findings. The SUPPRESSED-PACKAGE audit trail exists so QSAs can challenge
the scope decision.

## Design philosophy

pci-dss-mcp defaults to **high recall, moderate precision**. This is industry
consensus for compliance SAST (Brakeman, Semgrep, GoSec, OWASP SAMM): a
scanner that silently skips code fails the audit; a scanner that flags extra
findings is a triage problem, not an audit problem. Short version:
pci-dss-mcp is a compliance tool where false negatives (missed CHD leaks) are
catastrophes and false positives (noise on game code) are inconveniences. We
prefer the noise plus ergonomic exclusion over silent skips.

If you find yourself editing `.pci-dss-mcp-ignore` every day to suppress
individual findings, that is a signal the scoring is wrong — please file
an issue with the false-positive pattern so we can trim the signal weights
per the deterministic trim sequence captured in
`internal/keywords/payment_context_calibration_test.go`.

## Seeing what was excluded

Every compliance report includes one `SUPPRESSED-PACKAGE` INFO finding per
`exclude-package:` directive that matched at least one finding. Run:

```
./pci-dss-mcp generate_compliance_report /path/to/project | jq '.findings[] | select(.rule_id == "SUPPRESSED-PACKAGE")'
```

to list every excluded package alongside the count of findings that were
dropped. Share this with your QSA so the audit trail is explicit.

## Related directives

The following suppression mechanisms are complementary to `exclude-package:`:

- `rule: <RULE-ID> path: <path>` — suppress specific finding types in specific paths (existing).
- `<glob>:*` or `<glob>:N` — file-level or line-level suppression (existing).
- Inline `// pci-ignore: <reason>` comments — suppress individual findings at the source line (existing).
- `exclude-package: <glob>` — short-circuit package-level scanning (new in ).

Use `exclude-package:` when an entire package is out-of-scope. Use the other
mechanisms when only specific findings or files need scoping. Both kinds of
suppression are surfaced in the compliance report so the audit trail stays
intact.

## Taint analysis mode selection

The taint engine improves report precision by downgrading
transit-only cardholder-data findings (CHD in request bodies that get
tokenized and returned masked) from HIGH/MEDIUM to INFO. As of
taint analysis is **ON by default** for production scans.

**Use taint-ON (default) for:**

- CI/CD pipelines and pre-merge gates
- QSA audit scans -- auditors must see the precision-adjusted report
- Compliance reports shared with stakeholders
  from 14 HIGH / 7 MEDIUM under taint-OFF to 5 HIGH / 3 MEDIUM under
  taint-ON, eliminating 9 HIGH + 4 MEDIUM transit-only false positives)

**Use taint-OFF (opt-out) for:**

- Dev iteration during scanner rule tuning
- Fast feedback loops when investigating a specific finding class
- Debugging the taint engine itself

**How to opt out:**

- Library caller: `gen.GenerateFast(ctx, path)` instead of
  `gen.Generate(ctx, path)`. The two wrappers are byte-equivalent
  except for the `includeTaint` flag passed to `GenerateWithOptions`.
- MCP tool caller: pass `"include_taint": false` in the
  `generate_compliance_report` input. The schema is tri-state `*bool`,
  so omitting the field falls back to the precision-first default.

**Cost:** taint analysis adds 2-30 seconds to scan time depending on
project size. `go/packages.Load` dominates the overhead (single
front-loaded cost; subsequent scans inside the same session reuse the
loaded package graph).

**Graceful degradation:** if the `go` binary is missing, the module
cache is unavailable, or `packages.Load` fails, the scanner falls back
to taint-OFF automatically with a single `slog.Warn`. No configuration
required; the report still produces a valid result. This preserves the
offline-capability guarantee for air-gapped CI environments where
taint cannot run.
