# Roadmap

This file tracks the high-level development direction for `pci-dss-mcp`. For day-to-day issue tracking and milestones, see <https://github.com/shyshlakov/pci-dss-mcp/issues> and <https://github.com/shyshlakov/pci-dss-mcp/milestones>.

For released-version history, see [CHANGELOG.md](CHANGELOG.md).

Recently shipped (see [CHANGELOG.md](CHANGELOG.md) for full release notes):

- **SBOM generation (CycloneDX v1.6)** in v0.6.0, PCI DSS 6.3.2 software inventory, works offline
- **Dependency scanner privacy refactor** in v0.6.3, intersect-style OSV checks with no module-name leak
- **HTTP input taint detection** in v0.7.0, three new rule families (HTTP-INPUT-LOG / -ERROR / -PANIC) catching raw HTTP framework input flowing into log, error and panic sinks across gin, chi, gorilla/mux and net/http
- **HTTP input taint precision tuning** in v0.7.1, severity-aware emission with three-class field-name taxonomy (PAN/CHD, auth-secret, generic-ID), format-validator sanitizers (uuid.Parse / time.Parse / strconv / net.ParseIP / mail.ParseAddress / netip), gin recovery callback sources, format-verb-aware fmt.Errorf/Sprintf Stringer recognition, method-projector propagators, io.Copy ReverseFlow, and a new CRITICAL tier for validator.FieldError-rooted PAN-validation context. Cuts the dominant false-positive class on server-validated correlation IDs.

Planned features in rough priority order:

- **Dangerous sink expansion**, route HTTP input taint into SQL execution, outbound HTTP, template rendering, filesystem and redirect sinks (SQL injection, SSRF, XSS, path traversal, open redirect) plus insecure-random detection for security-named functions
- **SARIF v2.1.0 output**, industry-standard format for CI pipelines, VS Code inline annotations and GitHub Code Scanning alerts
- **Custom YAML rule engine**, declarative `.pci-mcp/rules/*.yaml` for user-authored detection patterns, taint sources and sinks, severity overrides and suppression globs (no recompile, no external binary)
- **Cross-service CHD flow mapping**, OpenAPI v3 / protobuf schema analysis across microservices to derive PCI DSS data flow diagrams (1.2.4)
- **Semgrep adapter**, optional external runner that maps Semgrep's Go ruleset to PCI DSS requirements with finding deduplication against internal scanners

Each feature ships with golden-fixture coverage. Release order may shift based on community feedback. [Open an issue](https://github.com/shyshlakov/pci-dss-mcp/issues) if one of these would unblock you sooner.

## Projected coverage impact

The planned features take PCI DSS v4.0.1 sub-requirement coverage from the current **15 / ~250** (6.0%) to a projected **17-19 / ~250** (~7.5%):

| Phase | New sub-requirement coverage | Notes |
|-------|------------------------------|-------|
| Dangerous sink expansion | (broadens **6.2.4**) significantly; adds detection for SQLi, SSRF, XSS, path traversal, open redirect | Closes the single biggest top-10 PCI gap (SQL injection) and four adjacent OWASP-class sink categories using the existing USER_INPUT taint engine |
| SARIF output | None, orthogonal output format | Pure tooling integration |
| Custom YAML rule engine | User-controllable extension, no built-in coverage delta | Lets users declare project-internal masker shapes, custom sources and sinks without recompiling |
| Cross-service CHD flow | **1.2.4** (data flow diagram accuracy); possibly **1.2.3** (network diagram) | Auto-derived from OpenAPI v3 + protobuf + k8s manifests |
| Semgrep adapter | (broadens existing **6.2.4**, **4.2.1**, **8.6.2**) | Optional external supplement; PCI value depends on remaining gap after dangerous-sink expansion ships |

**Why the ceiling is so low.** Roughly 95% of PCI DSS v4.0.1 sub-requirements describe operational, network, physical, and policy controls (incident response procedures, firewall configuration, physical access, vendor management, training records, log review processes) that are not detectable from source code alone. Pushing meaningfully beyond ~20 sub-requirements would require runtime network probing, log-pipeline inspection, or document analysis, which are intentionally out of scope for a code-time MCP tool. The remaining sub-requirements always need human QSA review.
