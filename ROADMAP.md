# Roadmap

This file tracks the high-level development direction for `pci-dss-mcp`. For day-to-day issue tracking and milestones, see <https://github.com/shyshlakov/pci-dss-mcp/issues> and <https://github.com/shyshlakov/pci-dss-mcp/milestones>.

For released-version history, see [CHANGELOG.md](CHANGELOG.md).

Planned features in rough priority order:

- **SBOM generation (CycloneDX v1.6)**, PCI DSS 6.3.2 software inventory, works offline
- **Reachability-aware dependency scanning**, `govulncheck` integration, unreachable CVEs downgrade to INFO
- **SARIF v2.1.0 output**, industry-standard format for CI pipelines and VS Code
- **Semgrep adapter**, map Semgrep's 5000+ rules to PCI DSS requirements
- **Cross-service CHD flow mapping**, OpenAPI/protobuf schema analysis across microservices

Each feature ships with golden-fixture coverage. Release order may shift based on community feedback. [Open an issue](https://github.com/shyshlakov/pci-dss-mcp/issues) if one of these would unblock you sooner.

## Projected coverage impact

The five planned features take PCI DSS v4.0.1 sub-requirement coverage from the current **14 / ~250** (5.6%) to a projected **16-18 / ~250** (~7%):

| Phase | New sub-requirement coverage | Notes |
|-------|------------------------------|-------|
| SBOM generation | **6.3.2** | Mandatory since 31 March 2025; currently zero coverage in any MCP tool |
| Reachability-aware deps | (deepens existing **6.3.3**); helps **11.3.1.1** when paired with SBOM | Improves precision of an existing rule; the SBOM + reachability pair closes the "manage all discovered vulns" loop |
| SARIF output | None, orthogonal output format | Pure tooling integration |
| Semgrep adapter | (broadens existing **6.2.4**, **4.2.1**, **8.6.2**) | Per Semgrep's own compliance docs, their PCI surface overlaps with ours; the real gain is rule **breadth** (~5000 rules), not new sub-requirements |
| Cross-service CHD flow | **1.2.4** (data flow diagram accuracy); possibly **1.2.3** (network diagram) | Auto-derived from OpenAPI v3 + protobuf + k8s manifests |

**Why the ceiling is so low.** Roughly 95% of PCI DSS v4.0.1 sub-requirements describe operational, network, physical, and policy controls (incident response procedures, firewall configuration, physical access, vendor management, training records, log review processes) that are not detectable from source code alone. Pushing meaningfully beyond ~20 sub-requirements would require runtime network probing, log-pipeline inspection, or document analysis, which are intentionally out of scope for a code-time MCP tool. The remaining sub-requirements always need human QSA review.
