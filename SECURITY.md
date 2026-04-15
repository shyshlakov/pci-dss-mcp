# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **pci-dss-mcp**, please report it
privately so it can be fixed before public disclosure.

**Preferred channel:** open a private security advisory via GitHub's
[Report a vulnerability](https://github.com/shyshlakov/pci-dss-mcp/security/advisories/new)
form. This keeps the report confidential until a fix is released.

**Alternative:** email the maintainer directly (see the commit history for
the address). Include:

- A description of the vulnerability
- Steps to reproduce (ideally a minimal case)
- Affected version(s)
- Your assessment of severity and impact

You can expect an initial response within **72 hours**. Please do not open
a public issue for security reports.

## Scope

In scope:

- The `pci-dss-mcp` binary and every package under the root Go module
  (`github.com/shyshlakov/pci-dss-mcp`)
- The MCP server transport and tool handlers
- The PCI DSS requirements database (`pcidb/`)

Out of scope:

- **`testdata/vulnerable-payment-service/`** — this directory is a synthetic
  Go module that **deliberately contains vulnerabilities and hardcoded
  secrets**. It is the golden regression fixture used to verify the
  scanner's detections. Findings inside this directory are intentional and
  are not vulnerabilities in pci-dss-mcp itself. Please do not file reports
  against fixture contents.
- Dependencies of the `testdata/vulnerable-payment-service/` module are
  pinned to specific versions (some with known CVEs) to keep the fixture
  reproducible. CVEs in fixture dependencies are tracked but not patched
  unless the fix is also applied to a companion fixture entry.
- Findings produced by running pci-dss-mcp against your own code are not
  vulnerabilities in pci-dss-mcp — they are what the tool is designed to
  report.

## Supported Versions

pci-dss-mcp is pre-1.0. Security fixes are applied to the `main` branch
only. Once v1.0 is released, this policy will be updated to cover the
latest minor version.

## Disclosure Process

1. Report received and acknowledged within 72 hours.
2. Initial assessment and severity classification within 7 days.
3. Fix developed on a private branch.
4. Coordinated disclosure: fix merged, release cut, public advisory
   published, reporter credited (unless anonymity is requested).

Thank you for helping keep pci-dss-mcp and its users safe.
