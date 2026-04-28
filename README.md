# pci-dss-mcp

> Static analysis MCP server for Go payment service codebases. Every detected PCI DSS v4.0.1 violation in a Go payment service codebase is mapped to the specific requirement number before the code ships.

[![Go Report Card](https://goreportcard.com/badge/github.com/shyshlakov/pci-dss-mcp?v=2)](https://goreportcard.com/report/github.com/shyshlakov/pci-dss-mcp)
[![License: MIT](https://img.shields.io/github/license/shyshlakov/pci-dss-mcp)](LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/shyshlakov/pci-dss-mcp/badge)](https://scorecard.dev/viewer/?uri=github.com/shyshlakov/pci-dss-mcp)
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.shyshlakov%2Fpci--dss--mcp-blue)](https://registry.modelcontextprotocol.io/v0/servers?search=pci-dss-mcp)
[![pci-dss-mcp MCP server](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp/badges/score.svg)](https://glama.ai/mcp/servers/shyshlakov/pci-dss-mcp)

---

## What it does

pci-dss-mcp is a stdio MCP server that runs 12 scanners, an orchestrator, and an AI triage engine over a Go payment service codebase. Each finding carries a `requirement_id` mapped to a specific PCI DSS v4.0.1 line item; see [docs/requirement-mapping.md](docs/requirement-mapping.md) for the canonical rule-to-requirement table and [testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md](testdata/vulnerable-payment-service/EXPECTED-FINDINGS.md) for live golden output.

### What pci-dss-mcp catches today

- **HTTP framework input flow into log / error / panic sinks.** Tier 1 frameworks (gin, chi, gorilla/mux, net/http (Go 1.22+), echo v4, fiber v2) and Tier 1 loggers (log/slog, logrus, zap, zerolog, logr, klog, hclog) ship in v0.7. Tier 2 (kratos, apex/log, charmbracelet/log) lands in v0.8. Tier 3 (fasthttp, beego, iris, httprouter, project-internal) is user-configurable via Phase 25 YAML once shipped. See [docs/http_input_taint.md](docs/http_input_taint.md).

### What pci-dss-mcp is NOT

- **Not a replacement for broad SAST.** Use Semgrep, CodeQL, or gosec for OWASP Top-10 and language-agnostic vulnerabilities.
- **Not a replacement for LLM-based code review.** pci-dss-mcp maps payment-specific issues to PCI DSS requirement IDs; LLM agents catch broad bugs via reasoning. The two layers compose.
- **Not Go-agnostic.** Go-specific AST patterns and taint flow tracing are what make the precision possible.
- **Not a QSA replacement.** Static analysis covers ~6% of PCI DSS v4.0.1 requirements. A Qualified Security Assessor must sign off on the rest.

## Install

### Go install (primary)

Requires **Go 1.25+**:

```bash
go install github.com/shyshlakov/pci-dss-mcp@latest
```

The binary lands at `$(go env GOPATH)/bin/pci-dss-mcp`. See [docs/install-from-source.md](docs/install-from-source.md) for PATH resolution, the macOS `codesign` provenance fix, cosign verification, and the MCP client JSON config.

### Docker (alternative)

```bash
docker pull ghcr.io/shyshlakov/pci-dss-mcp:v0.6.2
```

Useful for CI pipelines, QSA auditors who do not develop Go locally, or any environment without a host Go toolchain.

### MCP Registry

Listed as `io.github.shyshlakov/pci-dss-mcp` at [registry.modelcontextprotocol.io](https://registry.modelcontextprotocol.io/v0/servers?search=pci-dss-mcp). Auto-published on every tag.

## Usage

Add to your MCP client config (Claude Desktop `claude_desktop_config.json`, Cursor `.cursor/mcp.json`, or `claude mcp add` for Claude Code):

```json
{
  "mcpServers": {
    "pci-dss-mcp": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
        "--mount", "type=bind,src=/Users/you/go/src,dst=/Users/you/go/src,readonly",
        "ghcr.io/shyshlakov/pci-dss-mcp:v0.6.2"]
    }
  }
}
```

`src=` and `dst=` mirror the same absolute path so the container sees your code at the same path your host uses; prompts pass the normal host path with no translation. For the `go install` variant and per-client examples, see [docs/usage.md](docs/usage.md).

Two prompts to paste into your MCP client:

1. `Run pci-dss-mcp triage on /Users/you/payments-service. Use min_severity=MEDIUM and group findings by PCI DSS requirement.`
2. `Generate a PCI DSS compliance report for /Users/you/payments-service in JSON format. Show requirement-level pass/fail status and severity counts.`

## Tools

| Tool | Purpose | Docs |
|------|---------|------|
| `triage_findings` | All scanners + AI classification + file:line context in one call | [docs/triage_findings.md](docs/triage_findings.md) |
| `generate_compliance_report` | Raw requirement pass/fail report (orchestrator over all scanners) | [docs/generate_compliance_report.md](docs/generate_compliance_report.md) |
| `scan_pan_data` | PAN/SAD storage and logging (3.3.1, 3.4.1, 3.5.1) | [docs/scan_pan_data.md](docs/scan_pan_data.md) |
| `check_encryption` | Weak hashing, hardcoded keys, plain HTTP (4.2.1, 6.2.4) | [docs/check_encryption.md](docs/check_encryption.md) |
| `check_tls_config` | Insecure TLS configs (4.2.1) | [docs/check_tls_config.md](docs/check_tls_config.md) |
| `check_secrets_in_configs` | Credentials in config files (8.6.2) | [docs/check_secrets_in_configs.md](docs/check_secrets_in_configs.md) |
| `check_error_handling` | Error responses leaking sensitive context (6.2.4) | [docs/check_error_handling.md](docs/check_error_handling.md) |
| `check_auth_strength` | Hardcoded passwords, weak policy, missing MFA, webhook signatures (8.3.1, 8.3.6, 8.4.2, 8.6.2) | [docs/check_auth_strength.md](docs/check_auth_strength.md) |
| `audit_log_coverage` | Missing audit logs on payment flows (10.2.1) | [docs/audit_log_coverage.md](docs/audit_log_coverage.md) |
| `check_data_retention` | Missing TTL, sensitive storage, missing zeroing (3.2.1, 3.3.1) | [docs/check_data_retention.md](docs/check_data_retention.md) |
| `check_payment_page_scripts` | Missing CSP/SRI/nonce on payment pages (6.4.3, 11.6.1) | [docs/check_payment_page_scripts.md](docs/check_payment_page_scripts.md) |
| `check_dependencies` | Vulnerable Go dependencies via OSV (6.3.3); govulncheck-style privacy: no module names sent to OSV.dev. See [docs/check_dependencies.md](docs/check_dependencies.md#privacy). Also covers `update_vulnerability_db`. | [docs/check_dependencies.md](docs/check_dependencies.md) |
| `generate_sbom` | CycloneDX 1.6 SBOM from go.mod/go.sum (6.3.2) | [docs/generate_sbom.md](docs/generate_sbom.md) |
| `explain_requirement` | Look up a PCI DSS v4.0.1 requirement by ID | [docs/explain_requirement.md](docs/explain_requirement.md) |

All tools declare typed `OutputSchema`. See [docs/tools.md](docs/tools.md) for the catalog index and migration history.

## Documentation

- [docs/usage.md](docs/usage.md), client setup, prompt templates, suppressing findings
- [docs/severity.md](docs/severity.md), severity model and rule-to-severity mapping
- [docs/taint.md](docs/taint.md), taint analysis defaults and toggles
- [docs/scoping.md](docs/scoping.md), package exclusion and CDE scope
- [docs/comparison.md](docs/comparison.md), pci-dss-mcp vs Semgrep / CodeQL / gosec / Snyk Code
- [docs/ci-cd.md](docs/ci-cd.md), GitHub Actions and GitLab CI integration
- [docs/pci-coverage.md](docs/pci-coverage.md), PCI DSS v4.0.1 requirement coverage matrix
- [docs/install-from-source.md](docs/install-from-source.md), source build, cosign verification, reload
- [docs/requirement-mapping.md](docs/requirement-mapping.md), canonical rule_id to requirement_id table
- [CONTRIBUTING.md](CONTRIBUTING.md), development setup, fuzz targets
- [ROADMAP.md](ROADMAP.md), planned features
- [CHANGELOG.md](CHANGELOG.md), version history

## Status

Active development, pre v1.0. See [ROADMAP.md](ROADMAP.md) and [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).

---

*pci-dss-mcp is a static analysis tool. It cannot replace a Qualified Security Assessor. Use its output as input to your compliance process, not as the compliance itself.*
