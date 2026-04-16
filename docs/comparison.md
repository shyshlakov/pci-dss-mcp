# Why pci-dss-mcp?

pci-dss-mcp is **narrow and deep**. It only scans Go, it only checks PCI DSS v4.0.1, and it ships with compliance mapping baked in. It exists because broad SAST tools (Semgrep, CodeQL, gosec, Snyk Code) and LLM-based agentic code reviewers do not produce QSA-ready compliance output for Go payment services.

## What pci-dss-mcp does that other tools don't

**1. Every finding carries a PCI DSS requirement ID out of the box.**

pci-dss-mcp emits `requirement_id: "3.4.1"` on every finding and produces a per-requirement `PASS` / `FAIL` / `NOT_CHECKED` status table suitable for a QSA audit deliverable. For comparison:

- **[Semgrep's PCI DSS automation guide](https://semgrep.dev/blog/2025/from-gatekeepers-to-guardrails-automating-your-pci-v401-strategy/)** demonstrates rule examples for requirements 3.2-3.4, 6.2.4, 6.3.1, 6.3.2, 6.3.3, 8.6.2, and 10.2, but most of the 3.x examples rely on the user **writing a custom Semgrep rule** rather than a maintained ruleset. It does not map individual findings to requirement IDs automatically.
- **CodeQL** has no dedicated PCI DSS query suite. The default query suite is OWASP-style and customization requires writing QL queries.
- **gosec** maps its **59 rules** to CWE identifiers; there is **no PCI DSS mapping** in the upstream project.
- **Snyk Code** rules are tagged with CWE, OWASP Top 10, and SANS 25. Snyk offers a separate PCI DSS v4.0.1 Report (Early Access, Enterprise plans only) that aggregates findings against requirement 6.2.4, but **individual Snyk Code findings are not labeled with PCI DSS requirement numbers** in the default SAST output.

pci-dss-mcp is the only scanner on this list where you can call `generate_compliance_report` and get back a requirement-keyed report without writing a single custom rule.

**2. Taint analysis that knows the PCI SSC FAQ on non-persistent memory.**

Generic taint engines -- **Semgrep**, **Snyk Code** ([contextual dataflow](https://snyk.io/blog/analyze-taint-analysis-contextual-dataflow-snyk-code/)), **CodeQL** -- correctly track cardholder data flow source -> sink. But they do not know that the PCI Security Standards Council FAQ ["Should cardholder data be encrypted while in memory?"](https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/Should-cardholder-data-be-encrypted-while-in-memory/) explicitly allows cardholder data in non-persistent memory without byte-level encryption requirements. This ruling is domain knowledge, not something a generic tool implements.

pci-dss-mcp's taint engine implements the severity rule table derived from that FAQ:

| Flow | `PAN-KEYWORD` (3.3.1) | `PAN-TYPE` (3.5.1) |
|---|---|---|
| Flows to DB (stored) | keep HIGH + annotate | keep MEDIUM |
| Transit only (no DB) | **downgrade to INFO** | **suppressed entirely** per FAQ |
| Inconclusive | keep | keep |

The downgrade annotation on every affected finding literally says `(taint: transit-only, non-persistent memory per PCI SSC FAQ)`. This eliminates the overwhelming majority of PAN false positives on real Go payment services where request DTOs and API client models carry `CardNumber` / `CVV` fields purely in transit.

**3. MCP-native from the start.**

pci-dss-mcp runs as an [MCP](https://modelcontextprotocol.io) server inside Claude Desktop, Claude Code, and Cursor. There is no separate CLI to install, no dashboard to log into, no CI plugin to configure. The moment your editor agent sees a PCI DSS question, it calls the tool. Combined with filter parameters (`min_severity`, `rule_filter`, `limit`) and the [MCP spec 2025-06-18 `resource_link` content type](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), it fits cleanly into LLM-driven review workflows.

Other tools listed here -- Semgrep, CodeQL, gosec, Snyk Code -- are not MCP servers, and Claude Code is an MCP client, not a server. The MCP-tagged security tools that do exist ([Snyk agent-scan](https://github.com/snyk/agent-scan), [Enkrypt MCP Scan](https://www.enkryptai.com/mcp-scan), [Proximity](https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/)) scan MCP servers for security risks -- they are not MCP servers that scan code for compliance.

**4. Air-gap capable with no LLM API dependency.**

pci-dss-mcp is a plain Go binary that can run fully air-gapped. Twelve of the thirteen scanners are pure static analysis with zero network I/O. The one exception is `check_dependencies`, which defaults to `auto` mode (online OSV fetch with offline fallback); set `dep_scan_mode=offline` to force the local OSV cache path -- refreshable on a connected host via `update_vulnerability_db`, then carried into the isolated environment. This makes pci-dss-mcp usable in fintech CI/CD, bank networks, and isolated compliance environments where LLM-driven agents that call a hosted model cannot reach a backend.

(Semgrep CLI, CodeQL CLI, and gosec also run offline -- this is table stakes for non-LLM SAST tools. The differentiator is specifically against LLM-based code-review agents that require a hosted model API at runtime.)

## Feature comparison (verified against public sources)

| | pci-dss-mcp | Claude Code | Semgrep | CodeQL | gosec | Snyk Code |
|---|---|---|---|---|---|---|
| **Finding -> PCI DSS req ID** | built-in | -- (LLM reasoning) | partial, examples require custom rules | -- (no PCI suite) | CWE only | CWE / OWASP / SANS 25 (PCI report aggregated, Enterprise only) |
| **PCI SSC FAQ transit-CHD downgrade** | yes | -- | -- | -- | -- | -- |
| **Go taint analysis** | yes | via LLM reasoning | yes (free + pro) | yes | -- | yes |
| **Offline / air-gapped** | yes | no (Claude API) | yes CLI | yes CLI | yes | no (SaaS) |
| **MCP server** | yes | no (MCP client, not server) | -- | -- | -- | -- |
| **Determinism** | yes | LLM non-determinism | yes | yes | yes | yes |
| **License** | MIT | source-available | LGPL 2.1 (OSS core) | source-available | Apache-2 | proprietary (SaaS) |
| **Multi-language** | Go only | 30+ | 30+ | ~10 | Go only | 30+ |
| **QSA audit-ready report** | yes | -- | -- | -- | -- | -- |
