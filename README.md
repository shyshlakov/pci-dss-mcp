# pci-dss-mcp

> **Narrow-and-deep PCI DSS v4.0.1 compliance scanner for Go payment services, delivered as an MCP server.**
>
> Every finding maps to a specific PCI DSS requirement ID. Taint-aware cardholder data flow analysis with PCI SSC FAQ semantics. Runs inside Claude Desktop, Claude Code, and Cursor via the Model Context Protocol. Designed to complement broad security tools like Semgrep, CodeQL, and LLM-based agentic code review — not replace them.

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)

---

## What it does

pci-dss-mcp is a **static compliance scanner** for Go payment service codebases that checks code against **PCI DSS v4.0.1**. It runs as an MCP server, so your AI-assisted editor (Claude Desktop, Claude Code, Cursor) can invoke it directly during development.

**Instead of** `"Here's a list of 894 security issues, good luck prioritizing them"`, **you get** (real output, trimmed):

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
  Sensitive authentication data 'cvv' passed to logging function slog.Info
  Fix: Remove SAD from log output. SAD must not be retained after authorization per PCI DSS 3.3.1.
```

Every finding carries `requirement_id`, `severity`, `file_path`, `line`, and a triage hint so your AI editor can **verify the finding against the real code** and flag false positives automatically. See [docs/requirement-mapping.md](docs/requirement-mapping.md) for the canonical rule_id to requirement_id table.

### What pci-dss-mcp is NOT

- **Not a replacement for broad SAST.** Use Semgrep, CodeQL, or gosec for OWASP Top-10 and language-agnostic vulnerabilities.
- **Not a replacement for LLM-based code review.** pci-dss-mcp maps payment-specific issues to PCI DSS requirement IDs; LLM agents catch broad bugs via reasoning. The two layers compose.
- **Not Go-agnostic.** Go-specific AST patterns and taint flow tracing are what make the precision possible.
- **Not a QSA replacement.** Static analysis covers ~5.6% of PCI DSS v4.0.1 requirements. A Qualified Security Assessor must sign off on the rest.

See [docs/comparison.md](docs/comparison.md) for a detailed feature comparison with Semgrep, CodeQL, gosec, Snyk Code, and Claude Code.

## Install

pci-dss-mcp requires **Go 1.25+**. Two install paths:

### Quick install (released version)

```bash
go install github.com/shyshlakov/pci-dss-mcp@latest
```

This compiles the binary and drops it in `$(go env GOPATH)/bin/pci-dss-mcp`
(usually `~/go/bin/pci-dss-mcp` on macOS and Linux, `%USERPROFILE%\go\bin\pci-dss-mcp.exe` on Windows).

### Build from source (track main branch)

```bash
git clone https://github.com/shyshlakov/pci-dss-mcp.git
cd pci-dss-mcp
go install .
```

### Find the absolute path to your binary

The MCP client configs in the next section need an **absolute path**:

```bash
which pci-dss-mcp
# /Users/you/go/bin/pci-dss-mcp
```

If `which` returns nothing, use `echo "$(go env GOPATH)/bin/pci-dss-mcp"`.

### macOS provenance fix (required if you see SIGKILL)

macOS tags unsigned binaries with a `com.apple.provenance` attribute that can
cause `SIGKILL` when launched from a GUI-spawned MCP client. The reliable workaround:

```bash
codesign --force --sign - "$(which pci-dss-mcp)"
```

### Verify

```bash
pci-dss-mcp < /dev/null
# Expected output on stderr:
#   level=INFO msg="PCI DSS database loaded" requirements=250
#   level=INFO msg="starting MCP server on stdio"
```

## Setup

pci-dss-mcp runs over MCP stdio. **All client configs require the absolute path** — bare command names do not work because GUI clients do not inherit shell `PATH`.

### Claude Desktop

Edit `claude_desktop_config.json` (`~/Library/Application Support/Claude/` on macOS):

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

Restart Claude Desktop after saving.

### Claude Code

```bash
claude mcp add --scope user pci-dss-mcp -- "$(which pci-dss-mcp)"
```

Verify: `claude mcp list`

### Cursor

Edit `~/.cursor/mcp.json`:

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

### Reloading after a rebuild

- **Claude Desktop:** quit and relaunch
- **Claude Code:** `/mcp reload` or restart session
- **Cursor:** restart Cursor

## Use Cases

### 1. Triage overview

```
Run AI triage on this project and give me a prioritized overview:
severity distribution, top rules firing, and top items to review first.
```

### 2. Triage + focused drill-in

```
Triage this project for PCI DSS issues. Show me the CRITICAL findings
in detail with file:line and triage hints, then give counts for the
rest by severity.
```

### 3. Rule-specific triage

```
Run AI triage on all CRYPTO-HARDCODED-KEY findings in this project
and mark each as likely real vs false positive with reasoning.
```

### 4. Plain compliance report (no AI triage)

```
Generate a PCI DSS compliance report for this project — raw findings
without AI triage. Show requirement-level pass/fail status and
severity counts.
```

`triage_findings` is the recommended entry point for interactive scans — it runs all scanners, applies AI classification, and attaches file:line context in a single call. Use `generate_compliance_report` only when you need raw findings without triage (audit artifacts, CI pass/fail gates).

See [docs/usage.md](docs/usage.md) for more use cases: dependency checks, requirement lookup, false-positive tuning, subdirectory scans, audit-ready reports.

## Tools

pci-dss-mcp exposes **14 MCP tools**: 10 scanners, 1 orchestrator, 1 triage engine, 1 vulnerability DB updater, and 1 requirement lookup.

| Tool | Description |
|------|-------------|
| `generate_compliance_report` | Full compliance scan with per-requirement status, taint-aware severity, optional `min_severity` / `rule_filter` / `limit` |
| `triage_findings` | Enrich active findings with AI-triage-ready context (`ResourceLink` hints, imports, middleware chain) |
| `scan_pan_data` | PAN/CVV exposure in Go source and .env files (taint-aware) |
| `check_encryption` | Weak crypto, hardcoded keys, plain HTTP |
| `check_tls_config` | TLS misconfigurations (InsecureSkipVerify, weak ciphers, weak versions) |
| `check_secrets_in_configs` | Secrets in .env, .yaml, .json, .toml |
| `check_error_handling` | Error detail exposure in payment handlers |
| `check_auth_strength` | Weak passwords, missing MFA on payment routes |
| `audit_log_coverage` | Missing audit logging on payment handlers; 5-field PCI DSS 10.2.1 coverage |
| `check_data_retention` | CVV/PAN storage without TTL, missing memory zeroing |
| `check_payment_page_scripts` | CSP, SRI, nonce checks on Go handlers and HTML |
| `check_dependencies` | Go dependency vulnerabilities via OSV.dev (offline-capable) |
| `update_vulnerability_db` | Refresh the local OSV vulnerability cache for offline scans |
| `explain_requirement` | Look up any PCI DSS v4.0.1 requirement |

All tools declare typed `OutputSchema`. See [docs/tools.md](docs/tools.md) for parameters and example output.

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

### Why INFO findings matter

pci-dss-mcp never silently skips a detected pattern. When the scanner finds a sensitive pattern **and** verifies it is safe (e.g. transit-only DTO, banking domain context, dev-context secret, encrypted storage), it emits the finding as INFO instead of dropping it. This means:

- **For developers:** INFO findings confirm the scanner checked your code. No action required.
- **For auditors:** INFO findings provide an audit trail of what was evaluated.
- **For CI pipelines:** filter on `min_severity: "HIGH"` for pass/fail gates, but preserve INFO in the full report for audit evidence.

See [docs/severity.md](docs/severity.md) for the severity model.

## Coverage

pci-dss-mcp checks **14 PCI DSS v4.0.1 requirements** across 10 scanners covering Requirements 3, 4, 6, 8, 10, and 11. This is approximately 6% of the ~251 PCI DSS v4.0.1 defined-approach sub-requirements.

**Important:** Requirements outside scanner scope are marked `NOT_CHECKED` in the compliance report. `NOT_CHECKED` does not mean non-compliant — a QSA must verify these controls.

See [docs/pci-coverage.md](docs/pci-coverage.md) for the full coverage map.

## Documentation

- [Tools Reference](docs/tools.md) — all 14 tools with parameters and example output
- [Severity Model](docs/severity.md) — CRITICAL / HIGH / MEDIUM / LOW / INFO classification
- [Taint Analysis](docs/taint.md) — how taint-aware severity adjustment works
- [Taint Scoping](docs/scoping.md) — when to use taint ON vs fast mode
- [Use Cases](docs/usage.md) — additional prompt templates beyond the three above
- [Feature Comparison](docs/comparison.md) — pci-dss-mcp vs Semgrep, CodeQL, gosec, Snyk Code
- [CI/CD Integration](docs/ci-cd.md) — using pci-dss-mcp in pipelines
- [PCI DSS Coverage Map](docs/pci-coverage.md) — requirement coverage details

## Project Status

**Active development — pre v1.0.**

Core scanners and the MCP tool catalog are stable. The binding fixture regression suite in `testdata/vulnerable-payment-service/` is exercised on every change.

See [CHANGELOG.md](CHANGELOG.md) for the release history.

### Known limitations

- **Go only** — no Python / Java / .NET support planned
- **14 of ~250 PCI DSS v4.0.1 sub-requirements** covered (~5.6%) — the remaining ~94% require manual QSA review
- **Taint analysis needs module cache** — falls back to AST-only on failure

## Contributing

Contributions welcome. Before opening a PR:

1. **Run `make test`** — all 20+ packages must pass under `-race`
2. **Run `make test-fixture`** — the golden fixture regression gate is binding for any scanner change
3. **Match the atomic-commit convention** — conventional commit format (`feat(scope): ...`, `fix(scope): ...`)
4. **No emoji in code, comments, or commit messages**

New detection rules **must** follow the fixture TDD cycle: update `testdata/vulnerable-payment-service/` and `EXPECTED-FINDINGS.md` first (RED), implement the scanner change (GREEN), verify `make test-fixture` exits 0.

## Roadmap

Planned features in rough priority order:

- **SBOM generation (CycloneDX v1.5)** — PCI DSS 6.3.2 software inventory, works offline
- **Reachability-aware dependency scanning** — `govulncheck` integration, unreachable CVEs downgrade to INFO
- **SARIF v2.1.0 output** — industry-standard format for CI pipelines and VS Code
- **Semgrep adapter** — map Semgrep's 5000+ rules to PCI DSS requirements
- **Cross-service CHD flow mapping** — OpenAPI/protobuf schema analysis across microservices

Each feature ships with golden-fixture coverage. Release order may shift based on community feedback — [open an issue](https://github.com/shyshlakov/pci-dss-mcp/issues) if one of these would unblock you sooner.

### Projected coverage impact

The five planned features take PCI DSS v4.0.1 sub-requirement coverage from the current **14 / ~250** (5.6%) to a projected **16–18 / ~250** (~7%):

| Phase | New sub-requirement coverage | Notes |
|-------|------------------------------|-------|
| SBOM generation | **6.3.2** | Mandatory since 31 March 2025; currently zero coverage in any MCP tool |
| Reachability-aware deps | (deepens existing **6.3.3**); helps **11.3.1.1** when paired with SBOM | Improves precision of an existing rule; the SBOM + reachability pair closes the "manage all discovered vulns" loop |
| SARIF output | None — orthogonal output format | Pure tooling integration |
| Semgrep adapter | (broadens existing **6.2.4**, **4.2.1**, **8.6.2**) | Per Semgrep's own compliance docs, their PCI surface overlaps with ours; the real gain is rule **breadth** (~5000 rules), not new sub-requirements |
| Cross-service CHD flow | **1.2.4** (data flow diagram accuracy); possibly **1.2.3** (network diagram) | Auto-derived from OpenAPI v3 + protobuf + k8s manifests |

**Why the ceiling is so low.** Roughly 95% of PCI DSS v4.0.1 sub-requirements describe operational, network, physical, and policy controls — incident response procedures, firewall configuration, physical access, vendor management, training records, log review processes — that are not detectable from source code alone. Pushing meaningfully beyond ~20 sub-requirements would require runtime network probing, log-pipeline inspection, or document analysis, which are intentionally out of scope for a code-time MCP tool. The remaining sub-requirements always need human QSA review.

## License

MIT — see [LICENSE](LICENSE) for details.

---

*pci-dss-mcp is a static analysis tool. It cannot replace a Qualified Security Assessor. Use its output as input to your compliance process, not as the compliance itself.*
