# pci-dss-mcp

> **Narrow-and-deep PCI DSS v4.0.1 compliance scanner for Go payment services, delivered as an MCP server.**
>
> Every finding maps to a specific PCI DSS requirement ID. Taint-aware cardholder data flow analysis with PCI SSC FAQ semantics. Runs inside Claude Desktop, Claude Code, and Cursor via the Model Context Protocol. Designed to complement broad security tools like Semgrep, CodeQL, and LLM-based agentic code review — not replace them.

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)

---

## Table of Contents

- [What it does in 60 seconds](#what-it-does-in-60-seconds)
- [Example: the bundled vulnerable test project](#example-the-bundled-vulnerable-test-project)
- [Why pci-dss-mcp?](#why-pci-dss-mcp)
- [Install](#install)
- [Setup](#setup)
- [Use Cases](#use-cases)
- [Tools](#tools)
- [Taint Analysis](#taint-analysis)
- [Suppressing Findings](#suppressing-findings)
- [Coverage](#coverage)
- [Documentation](#documentation)
- [Project Status](#project-status)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## What it does in 60 seconds

pci-dss-mcp is a **static compliance scanner** for Go payment service codebases that checks code against **PCI DSS v4.0.1**. It runs as an MCP server, so your AI-assisted editor (Claude Desktop, Claude Code, Cursor) can invoke it directly during development.

**Instead of:**

```
"Here's a list of 894 security issues, good luck prioritizing them"
```

**You get** (real output on the bundled `testdata/vulnerable-payment-service/` fixture, trimmed):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PCI DSS v4.0.1 Compliance Report
Target: testdata/vulnerable-payment-service
Duration: 1957ms | Files: 615 | Lines: 9142
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

40 CRITICAL, 80 HIGH, 25 MEDIUM findings
(0 LOW, 35 INFO informational findings not shown)

--- Requirement 3: Protect Stored Account Data ---

[CRITICAL] 3.3.1 -- SAD Not Retained After Authorization
  internal/service/tokens/logging.go:11
  Sensitive cardholder data 'cardNumber' passed to logging function slog.Info
  Fix: Remove sensitive data from log output. Log a masked or tokenized reference instead.

[CRITICAL] 3.2.1 -- Data Retention and Disposal
  internal/cache/sensitive_redis.go:10
  Redis Set with TTL=0 on sensitive data -- data persists indefinitely. PCI DSS 3.2.1
  prohibits storing SAD after authorization.
  Fix: Set an explicit TTL (e.g., 5*time.Minute) for sensitive data.

[HIGH] 3.3.1 -- SAD Not Retained After Authorization
  internal/storage/postgres/model/leaked.go:5
  Struct field 'CVV' may expose cardholder data, requires manual review (LOW confidence)
  Fix: Verify if this field contains actual cardholder data. Use tokenized references if so.
  Also satisfies: 3.3.1.2

--- Requirement 4: Protect Cardholder Data with Strong Cryptography ---
...
```

Findings are grouped by PCI DSS requirement category and sorted CRITICAL → HIGH → MEDIUM within each group. The real output uses absolute file paths (shortened to repo-relative form above for readability). Every finding carries a line number, the rule description, and a concrete `Fix:` suggestion. The full report continues through Requirements 4, 6, 8, 10, and 11 followed by a `Requirements Summary` and a `Suppression Audit` section when any findings are suppressed.

Every finding carries `requirement_id`, `severity`, `file_path`, `line`, and a triage hint so your AI editor can **verify the finding against the real code** using its own `Read`/`Grep` tools — and flag false positives automatically.

## Example: the bundled vulnerable test project

pci-dss-mcp ships with a synthetic vulnerable Go payment service under
[`testdata/vulnerable-payment-service/`](testdata/vulnerable-payment-service/).
It's a self-contained Go module with intentional PCI DSS violations covering
every production detection rule, plus clean counter-examples. You can run
pci-dss-mcp against it without any external project:

```
# In a Claude Code / Cursor / Claude Desktop session with pci-dss-mcp wired in:
Run generate_compliance_report on testdata/vulnerable-payment-service
and show me the per-requirement breakdown.
```

Claude will invoke the tool and return a structured report. A single finding
in the `findings` array looks like this (real output from `panscanner`,
optional fields omitted when empty):

```json
{
  "rule_id": "PAN-KEYWORD",
  "severity": "CRITICAL",
  "requirement_id": "3.3.1",
  "file_path": "/abs/path/to/internal/storage/card_model.go",
  "line": 14,
  "column": 2,
  "description": "Struct field 'CardNumber' exposes cardholder data in payment context (HIGH confidence)",
  "suggestion": "Use tokenized or encrypted references instead of raw cardholder data.",
  "related_requirements": ["3.3.1.2"]
}
```

The full `scanner.Finding` type also carries optional fields
(`confidence`, `dev_context`, `code_snippet`, `triage_hint`, `fix_hint`,
`middleware_detected`, `sql_pattern_matched`) that scanners populate
when they have that context — see `scanner/scanner.go` for the
authoritative schema.

To see the recommended AI-verified workflow, use [Use Case #2](#2-full-compliance-scan--ai-verified-triage-recommended-workflow)
below: Claude chains `generate_compliance_report` → `triage_findings` →
its own `Read`/`Grep` tools and produces a CONFIRMED / FALSE POSITIVE /
MANUAL REVIEW classification for each finding.

**Why this works:** pci-dss-mcp gives a structured layer (requirement IDs,
severity, taint annotations, file/line refs, triage hints), and Claude's
own reasoning + file-reading tools do the adversarial verification pass on
top. The two layers compose naturally — pci-dss-mcp does not bake an LLM
verification loop into the server.

## Why pci-dss-mcp?

pci-dss-mcp is **narrow and deep**. It only scans Go, it only checks PCI DSS v4.0.1, and it ships with compliance mapping baked in. It exists because broad SAST tools (Semgrep, CodeQL, gosec, Snyk Code) and LLM-based agentic code reviewers do not produce QSA-ready compliance output for Go payment services.

### What pci-dss-mcp does that other tools don't

**1. Every finding carries a PCI DSS requirement ID out of the box.**

pci-dss-mcp emits `requirement_id: "3.4.1"` on every finding and produces a per-requirement `PASS` / `FAIL` / `NOT_CHECKED` status table suitable for a QSA audit deliverable. For comparison:

- **[Semgrep's PCI DSS automation guide](https://semgrep.dev/blog/2025/from-gatekeepers-to-guardrails-automating-your-pci-v401-strategy/)** demonstrates rule examples for requirements 3.2-3.4, 6.2.4, 6.3.1, 6.3.2, 6.3.3, 8.6.2, and 10.2, but most of the 3.x examples rely on the user **writing a custom Semgrep rule** rather than a maintained ruleset. It does not map individual findings to requirement IDs automatically.
- **CodeQL** has no dedicated PCI DSS query suite. The default query suite is OWASP-style and customization requires writing QL queries.
- **gosec** maps its **59 rules** to CWE identifiers; there is **no PCI DSS mapping** in the upstream project.
- **Snyk Code** rules are tagged with CWE, OWASP Top 10, and SANS 25. Snyk offers a separate PCI DSS v4.0.1 Report (Early Access, Enterprise plans only) that aggregates findings against requirement 6.2.4, but **individual Snyk Code findings are not labeled with PCI DSS requirement numbers** in the default SAST output.

pci-dss-mcp is the only scanner on this list where you can call `generate_compliance_report` and get back a requirement-keyed report without writing a single custom rule.

**2. Taint analysis that knows the PCI SSC FAQ on non-persistent memory.**

Generic taint engines — **Semgrep**, **Snyk Code** ([contextual dataflow](https://snyk.io/blog/analyze-taint-analysis-contextual-dataflow-snyk-code/)), **CodeQL** — correctly track cardholder data flow source → sink. But they do not know that the PCI Security Standards Council FAQ ["Should cardholder data be encrypted while in memory?"](https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/Should-cardholder-data-be-encrypted-while-in-memory/) explicitly allows cardholder data in non-persistent memory without byte-level encryption requirements. This ruling is domain knowledge, not something a generic tool implements.

pci-dss-mcp's taint engine implements the severity rule table derived from that FAQ:

| Flow | `PAN-KEYWORD` (3.3.1) | `PAN-TYPE` (3.5.1) |
|---|---|---|
| Flows to DB (stored) | keep HIGH + annotate | keep MEDIUM |
| Transit only (no DB) | **downgrade to INFO** | **suppressed entirely** per FAQ |
| Inconclusive | keep | keep |

The downgrade annotation on every affected finding literally says `(taint: transit-only, non-persistent memory per PCI SSC FAQ)`. This eliminates the overwhelming majority of PAN false positives on real Go payment services where request DTOs and API client models carry `CardNumber` / `CVV` fields purely in transit.

**3. MCP-native from the start.**

pci-dss-mcp runs as an [MCP](https://modelcontextprotocol.io) server inside Claude Desktop, Claude Code, and Cursor. There is no separate CLI to install, no dashboard to log into, no CI plugin to configure. The moment your editor agent sees a PCI DSS question, it calls the tool. Combined with filter parameters (`min_severity`, `rule_filter`, `limit`) and the [MCP spec 2025-06-18 `resource_link` content type](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), it fits cleanly into LLM-driven review workflows.

Other tools listed here — Semgrep, CodeQL, gosec, Snyk Code — are not MCP servers, and Claude Code is an MCP client, not a server. The MCP-tagged security tools that do exist ([Snyk agent-scan](https://github.com/snyk/agent-scan), [Enkrypt MCP Scan](https://www.enkryptai.com/mcp-scan), [Proximity](https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/)) scan MCP servers for security risks — they are not MCP servers that scan code for compliance.

**4. Air-gap capable with no LLM API dependency.**

pci-dss-mcp is a plain Go binary that can run fully air-gapped. Twelve of the thirteen scanners are pure static analysis with zero network I/O. The one exception is `check_dependencies`, which defaults to `auto` mode (online OSV fetch with offline fallback); set `dep_scan_mode=offline` to force the local OSV cache path — refreshable on a connected host via `update_vulnerability_db`, then carried into the isolated environment. This makes pci-dss-mcp usable in fintech CI/CD, bank networks, and isolated compliance environments where LLM-driven agents that call a hosted model cannot reach a backend.

(Semgrep CLI, CodeQL CLI, and gosec also run offline — this is table stakes for non-LLM SAST tools. The differentiator is specifically against LLM-based code-review agents that require a hosted model API at runtime.)

### What pci-dss-mcp is NOT

- **Not a replacement for broad SAST.** Use Semgrep, CodeQL, or gosec for OWASP Top-10, generic injection flaws, and language-agnostic vulnerabilities. pci-dss-mcp deliberately covers a narrow slice (PCI DSS v4.0.1 on Go) that those tools don't map to compliance-ready output.
- **Not a replacement for LLM-based code review.** Tools like Claude Code's agentic review loop give you broad, context-aware vulnerability triage across any language with adversarial verification. pci-dss-mcp runs alongside them: the LLM agent catches broad bugs via its own reasoning, and pci-dss-mcp maps payment-specific issues to PCI DSS requirement IDs for your QSA deliverable. The two layers compose — one reasoning, one deterministic.
- **Not a Go-agnostic scanner.** If your payment code is Python, Java, or .NET, pci-dss-mcp cannot help — and this is intentional. The Go-specific AST patterns, taint flow tracing, and payment-context scoring are what make the precision possible.
- **Not a QSA replacement.** Static analysis covers approximately 6% of PCI DSS v4.0.1 requirements (14 of ~251 defined-approach sub-requirements). The remaining 94% require organizational policy review, network architecture audit, physical security verification, and operational procedure assessment — a Qualified Security Assessor must sign off on those.

### Feature comparison (verified against public sources)

| | pci-dss-mcp | Claude Code | Semgrep | CodeQL | gosec | Snyk Code |
|---|---|---|---|---|---|---|
| **Finding → PCI DSS req ID** | ✓ built-in | — (LLM reasoning) | partial, examples require custom rules | — (no PCI suite) | CWE only | CWE / OWASP / SANS 25 (PCI report aggregated, Enterprise only) |
| **PCI SSC FAQ transit-CHD downgrade** | ✓ | — | — | — | — | — |
| **Go taint analysis** | ✓ | via LLM reasoning | ✓ (free + pro) | ✓ | — | ✓ |
| **Offline / air-gapped** | ✓ | ✗ (Claude API) | ✓ CLI | ✓ CLI | ✓ | ✗ (SaaS) |
| **MCP server** | ✓ | ✗ (MCP client, not server) | — | — | — | — |
| **Determinism** | ✓ | LLM non-determinism | ✓ | ✓ | ✓ | ✓ |
| **License** | MIT | source-available ¹ | LGPL 2.1 (OSS core) ² | source-available ³ | Apache-2 | proprietary (SaaS) |
| **Multi-language** | ✗ Go only | ✓ | ✓ 30+ | ✓ ~10 | ✗ Go only | ✓ |
| **QSA audit-ready report** | ✓ | — | — | — | — | — |

¹ Claude Code source is published on GitHub but under Anthropic Commercial Terms of Service, not an OSI-approved open-source license.
² Since 2024 Semgrep's maintained rule packs have shifted from LGPL 2.1 to the non-OSI "Semgrep Rules License v1.0"; the core Semgrep CE engine remains LGPL 2.1.
³ CodeQL queries are MIT-licensed; the CLI binary is free for public/OSS/academic/CI use per the GitHub CodeQL Terms, but private codebases require GitHub Advanced Security.

## Install

pci-dss-mcp requires **Go 1.25+**. Two install paths:

### Quick install (released version)

```bash
go install github.com/shyshlakov/pci-dss-mcp@latest
```

This compiles the binary and drops it in `$(go env GOPATH)/bin/pci-dss-mcp`
(usually `~/go/bin/pci-dss-mcp` on macOS and Linux, `%USERPROFILE%\go\bin\pci-dss-mcp.exe` on Windows).

### Build from source (track main branch)

Recommended when you want the latest scanner accuracy fixes before a tag lands:

```bash
git clone https://github.com/shyshlakov/pci-dss-mcp.git
cd pci-dss-mcp
go install .
```

`go install .` builds the binary and places it in the same `$(go env GOPATH)/bin/`
location as the quick install path above, so the setup instructions below work
for both install methods.

### Find the absolute path to your binary

The MCP client configs in the next section need an **absolute path**. Find yours:

```bash
which pci-dss-mcp
# /Users/you/go/bin/pci-dss-mcp
```

If `which` returns nothing, your `$(go env GOPATH)/bin` is not on the shell PATH. Use:

```bash
echo "$(go env GOPATH)/bin/pci-dss-mcp"
```

You will need this path in every Setup step below. Replace occurrences of
`/absolute/path/to/pci-dss-mcp` with your actual path.

### macOS provenance fix (required if you see SIGKILL)

macOS tags unsigned binaries with a `com.apple.provenance` attribute that can
cause `SIGKILL` when launched from a GUI-spawned MCP client (Claude Desktop,
Cursor). On macOS 15 Sequoia and later, `com.apple.provenance` is system-
protected and **`xattr -d`/`xattr -c` silently no-op on it** — the tag is
not actually removed. The reliable workaround is an ad-hoc code signature:

```bash
codesign --force --sign - "$(which pci-dss-mcp)"
```

This replaces the provenance marker with an ad-hoc signature and is enough
to satisfy Gatekeeper for GUI-spawned processes. Terminal-launched runs
(`pci-dss-mcp < /dev/null`) usually work without the fix, so test through
your MCP client if you want to confirm it is needed.

### Verify

```bash
pci-dss-mcp < /dev/null
# Expected output on stderr:
#   level=INFO msg="PCI DSS database loaded" requirements=250
#   level=INFO msg="starting MCP server on stdio"
# Process exits on EOF from /dev/null. No MCP client needed for this smoke check.
```

## Setup

pci-dss-mcp runs over MCP stdio. Wire it into any MCP-capable client. **All
client configs below require the absolute path** — bare command names do not
work because GUI clients (Claude Desktop, Cursor) do not inherit shell `PATH`.

### Claude Desktop

Edit `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "pci-dss-mcp": {
      "command": "/absolute/path/to/pci-dss-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Replace `/absolute/path/to/pci-dss-mcp` with the output of `which pci-dss-mcp`.

Config file location:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

Restart Claude Desktop after saving.

### Claude Code

Add via CLI with **user scope** so the server is available across all projects:

```bash
claude mcp add --scope user pci-dss-mcp -- "$(which pci-dss-mcp)"
```

Without `--scope user`, Claude Code registers the server in the current
directory's `.mcp.json` only. `--scope user` writes to `~/.claude/mcp.json`,
making the server visible in every Claude Code session.

Verify with:

```bash
claude mcp list
# pci-dss-mcp: /Users/you/go/bin/pci-dss-mcp - ✓ Connected
```

Then open a Claude Code session and run `/mcp` to see `pci-dss-mcp` in the
server list along with its tools.

### Cursor

Edit `~/.cursor/mcp.json` (global) or `<project>/.cursor/mcp.json`
(project-scoped):

```json
{
  "mcpServers": {
    "pci-dss-mcp": {
      "type": "stdio",
      "command": "/absolute/path/to/pci-dss-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

Replace `/absolute/path/to/pci-dss-mcp` with the output of `which pci-dss-mcp`.
Restart Cursor.

### Reloading after a rebuild

MCP clients cache the binary process. When you rebuild pci-dss-mcp, the old process keeps running until the client reloads:

- **Claude Desktop:** quit and relaunch the app
- **Claude Code:** `/mcp reload` or restart the CLI session
- **Cursor:** restart Cursor

## Use Cases

Concrete prompt templates to paste into any MCP-capable client. All examples assume the agent will invoke pci-dss-mcp tools automatically — you don't need to name the tools explicitly.

### 1. Quick scan before a commit

```
Run a PCI DSS compliance scan on the current project and show me only
HIGH and CRITICAL findings. Skip INFO noise.
```

Under the hood, Claude will call `generate_compliance_report` with `min_severity: "HIGH"`. Fast, focused, fits in any context window.

### 2. Full compliance scan + AI-verified triage (recommended workflow)

```
Run a full PCI DSS compliance scan on this project, then run AI triage
on the MEDIUM+ findings and classify each as CONFIRMED, FALSE POSITIVE,
or NEEDS MANUAL REVIEW. For each CONFIRMED finding, explain the attack
path and suggest a concrete fix.
```

This is the two-step workflow from the [bundled vulnerable test project example](#example-the-bundled-vulnerable-test-project) above. Claude will:

1. Call `generate_compliance_report` (taint ON by default)
2. Call `triage_findings` to enrich active findings with `ResourceLink` hints
3. Use its own `Read`/`Grep` tools on the hinted files to verify each finding against real architecture context
4. Produce a CONFIRMED / FALSE POSITIVE classification with attack-path reasoning

Total wall time: ~2-4 minutes on a 2,000-3,000-file Go payment service.

### 3. CI-style gate (fail fast)

```
Scan this project with pci-dss-mcp and return ONLY findings with severity
HIGH or above. If there are zero such findings, say "PASS". Otherwise
list the file:line of each finding.
```

Agent-friendly format for a pre-commit or PR-gate script.

### 4. Dependency vulnerability check

```
Check go.mod for vulnerable dependencies per PCI DSS 6.3.3. For any
HIGH or CRITICAL CVE, show the fix command and the PCI DSS remediation
SLA (30 days for HIGH).
```

Triggers `check_dependencies` against OSV.dev. Works offline against a warm `~/.cache/osv` if you run `update_vulnerability_db` first.

### 5. Explain a specific requirement

```
What does PCI DSS requirement 3.3.1 mean in plain English, and what do
I need to change in a Go codebase to comply?
```

Triggers `explain_requirement` — no scan required.

### 6. Real-world triage / false-positive tuning

```
Run pci-dss-mcp on this project. For each HIGH and MEDIUM finding, read the
surrounding code, cross-reference with PCI DSS requirement text via
explain_requirement, and tell me whether this is a real violation or a
false positive given the architecture. For false positives, draft a
one-line `pci-ignore` comment with a concrete reason I can paste into
the code.
```

Use this when onboarding pci-dss-mcp to a new project. The first pass always surfaces some context-dependent FPs; this prompt makes Claude do the triage and hand you ready-to-paste suppression comments.

### 7. Scan a subdirectory

```
Scan only ./internal/payment for PCI DSS violations. Ignore the rest of
the project.
```

pci-dss-mcp accepts any directory path — useful for monorepos where only one package handles cardholder data.

### 8. Audit-ready compliance report

```
Generate a PCI DSS v4.0.1 compliance report for this project in a
format I can attach to a QSA audit package. Include: per-requirement
PASS/FAIL/NOT_CHECKED status, list of findings grouped by requirement,
suppressions with reasons, and the 30/90-day remediation SLAs for each
HIGH/CRITICAL.
```

`NOT_CHECKED` requirements are not non-compliant — they're outside the scanner's static-analysis scope and must be verified manually by a QSA.

## Tools

pci-dss-mcp exposes **14 MCP tools**: 10 scanners, 1 orchestrator, 1 triage engine, 1 vulnerability DB updater, and 1 requirement lookup.

| Tool | Description |
|------|-------------|
| `generate_compliance_report` | Full compliance scan with per-requirement status, taint-aware severity, optional `min_severity` / `rule_filter` / `limit` |
| `triage_findings` | Enrich active findings with AI-triage-ready context (`ResourceLink` hints, imports, middleware chain, triage hints) — skips verified-OK markers automatically |
| `scan_pan_data` | PAN/CVV exposure in Go source and .env files (taint-aware) |
| `check_encryption` | Weak crypto, hardcoded keys, plain HTTP |
| `check_tls_config` | TLS misconfigurations (InsecureSkipVerify, weak ciphers, weak versions) |
| `check_secrets_in_configs` | Secrets in .env, .yaml, .json, .toml |
| `check_error_handling` | Error detail exposure in payment handlers |
| `check_auth_strength` | Weak passwords, missing MFA on payment routes (delegation-wrapper aware) |
| `audit_log_coverage` | Missing audit logging on payment handlers; 5-field PCI DSS 10.2.1 coverage |
| `check_data_retention` | CVV/PAN storage without TTL, missing memory zeroing (broad control-flow coverage) |
| `check_payment_page_scripts` | CSP, SRI, nonce checks on Go handlers and HTML |
| `check_dependencies` | Go dependency vulnerabilities via OSV.dev (offline-capable) |
| `update_vulnerability_db` | Refresh the local OSV vulnerability cache for offline scans |
| `explain_requirement` | Look up any PCI DSS v4.0.1 requirement |

All tools declare typed `OutputSchema` for MCP spec 2025-06-18 clients. See [docs/tools.md](docs/tools.md) for parameters and example output.

## Taint Analysis

pci-dss-mcp implements flow-based severity adjustment via `go/packages` type-aware analysis in the [`internal/taint`](internal/taint) package. When enabled, the PAN scanner distinguishes cardholder data in transit (request DTOs, API client models) from cardholder data at rest (DB models), downgrading false-positive HIGH findings on transit fields to INFO and suppressing `PAN-TYPE` findings entirely per the PCI SSC FAQ on non-persistent memory encryption.

### Enabling

Taint analysis is **on by default**. The `generate_compliance_report` MCP tool runs with `include_taint: true` unless you explicitly pass `include_taint: false`:

```json
{
  "name": "generate_compliance_report",
  "arguments": {
    "path": "/path/to/go/project"
  }
}
```

To opt out (fast dev-iteration mode), pass `include_taint: false`.

Library callers can use `gen.GenerateFast(ctx, path)` as the equivalent opt-out wrapper.

### Performance cost

Taint analysis loads the full Go module via `go/packages`, which takes **5-30 seconds** depending on module size and transitive dependency count. A 30-second hard ceiling is enforced; on timeout, the scanner falls back to AST-only analysis with a warning logged to stderr (graceful degradation).

### Requirements

- `go` binary on `PATH` (checked by `go version`)
- Target project must type-check cleanly (no missing imports, no syntax errors)
- Module cache pre-populated if running offline — `go list` may fetch from `GOPROXY`

### Hardening recommendation

When running taint analysis on untrusted project paths (for example in CI against third-party code), set `GOFLAGS=-mod=readonly` to prevent `go list` from fetching modules from attacker-controlled proxies:

```bash
GOFLAGS=-mod=readonly pci-dss-mcp
```

### What taint analysis does

| Rule | Without taint | With `include_taint=true` |
|------|---------------|---------------------------|
| `PAN-KEYWORD` on CVV/PAN struct field | HIGH (unconditional) | HIGH if field flows to DB storage sink; INFO if transit-only (DTO, API client); HIGH if inconclusive |
| `PAN-TYPE` on `string` CHD field | MEDIUM (unconditional) | MEDIUM if field flows to DB storage sink; **suppressed entirely** if transit-only per PCI SSC FAQ |
| `ERR-LEAK` | unchanged | unchanged (deferred to ) |
| `PAN-LOGGER` | unchanged | unchanged (deferred to ) |

## Suppressing Findings

Add `pci-ignore` comments to suppress known false positives:

```go
var testKey = "not-a-real-key" // pci-ignore: test fixture
```

```yaml
api_key: test-key-123  # pci-ignore: non-production test config
```

Or use a `.pci-dss-mcp-ignore` file in the project root:

```
testdata/**
config/test.json:*
config/prod.json:15
```

Suppressed findings appear as `SUPPRESSED` in reports — **never silently dropped**. Auditors must see what was suppressed and why.

See [docs/severity.md](docs/severity.md) for the severity model.

## Coverage

pci-dss-mcp checks **14 PCI DSS v4.0.1 requirements** across 10 scanners covering Requirements 3, 4, 6, 8, 10, and 11. This is approximately 6% of the ~251 PCI DSS v4.0.1 defined-approach sub-requirements.

**Important:** Static analysis cannot verify organizational policies, physical security, network architecture, or operational procedures. Requirements outside scanner scope are marked `NOT_CHECKED` in the compliance report. `NOT_CHECKED` does not mean non-compliant — a Qualified Security Assessor (QSA) must verify these controls.

See [docs/pci-coverage.md](docs/pci-coverage.md) for the full coverage map.

## Documentation

- [Tools Reference](docs/tools.md) — all 14 tools with parameters and example output
- [Severity Model](docs/severity.md) — CRITICAL / HIGH / MEDIUM / LOW / INFO classification
- [Taint Scoping](docs/scoping.md) — when to use taint ON vs fast mode
- [CI/CD Integration](docs/ci-cd.md) — using pci-dss-mcp in pipelines
- [PCI DSS Coverage Map](docs/pci-coverage.md) — requirement coverage details

## Project Status

**Active development — pre v1.0.**

Core scanners and the MCP tool catalog are stable and the binding fixture
regression suite in `testdata/vulnerable-payment-service/` is exercised on
every change. Planned areas of future work include SBOM generation
(PCI DSS 6.3.2), `govulncheck` integration alongside the existing OSV
dependency scanner, SARIF output for CI pipelines, Semgrep adapter, and
cross-service cardholder-data-flow mapping via OpenAPI/protobuf schemas.

See [CHANGELOG.md](CHANGELOG.md) for the release history.

### Known limitations

- **Go only** — no Python / Java / .NET support planned
- **14 of ~251 PCI DSS v4.0.1 defined-approach sub-requirements** covered (~6%) — the remaining 94% require manual QSA review
- **Taint analysis needs module cache** — `go list` must be able to resolve imports; falls back to AST-only on failure

## Contributing

Contributions welcome. Before opening a PR:

1. **Run `make test`** — all 20+ packages must pass under `-race`
2. **Run `make test-fixture`** — the golden fixture regression gate is binding for any scanner change
3. **Match the atomic-commit convention** — one logical change per commit, conventional commit format (`feat(scope): ...`, `fix(scope): ...`)
4. **No emoji in code, comments, or commit messages**

New detection rules **must** follow the fixture TDD cycle: update `testdata/vulnerable-payment-service/` and `EXPECTED-FINDINGS.md` first (RED), implement the scanner change (GREEN), verify `make test-fixture` exits 0. Skipping this cycle is a PR-blocking offense.

## Roadmap

pci-dss-mcp is in active development. The following user-facing features are planned for upcoming releases, in rough priority order:

- **SBOM generation (CycloneDX v1.5)** — `generate_sbom(path)` will produce a standards-compliant software inventory with name, version, purl, license, and SHA-256 per component, satisfying the now-mandatory PCI DSS 6.3.2. Works offline from the local Go module cache, no network required.

- **Reachability-aware dependency scanning** — `check_dependencies` will integrate `govulncheck` to prove whether vulnerable functions are actually called. Unreachable CVEs automatically downgrade to INFO, eliminating false HIGH alerts on unused code paths. Reachable CVEs surface the full call stack (`main → handler → service → vulnerable_func`) as evidence.

- **SARIF v2.1.0 output** — `generate_compliance_report(output_format="sarif")` will emit industry-standard SARIF JSON consumable by VS Code SARIF Viewer, `github/codeql-action/upload-sarif`, and any CI pipeline that speaks SARIF. PCI DSS requirement IDs and CWE IDs embedded per finding for inline PR annotations.

- **Semgrep adapter** — optional integration that runs `semgrep --sarif`, parses its 5000+ security rules, and maps them to PCI DSS requirements. Duplicate findings resolved in favor of internal scanners (which carry richer payment-context metadata). Graceful skip if Semgrep is not installed.

- **Cross-service cardholder-data-flow mapping** — `map_cardholder_data_flow(specs_dir)` will parse OpenAPI v3 and protobuf schemas across a microservice fleet to auto-detect which services handle CHD, build the data-flow graph, flag full-PAN APIs, and recommend scope reduction. Findings map to PCI DSS 1.2.4 (data flow diagram accuracy).

Each feature ships with golden-fixture coverage and only after `make test-fixture` passes. Release order may shift based on community feedback — [open an issue](https://github.com/shyshlakov/pci-dss-mcp/issues) if one of these would unblock you sooner.

## License

MIT — see [LICENSE](LICENSE) for details.

---

*pci-dss-mcp is a static analysis tool. It cannot replace a Qualified Security Assessor. Use its output as input to your compliance process, not as the compliance itself.*
