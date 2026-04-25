# Use Cases

Prompt templates to paste into any MCP-capable client. All examples assume the agent will invoke pci-dss-mcp tools automatically.

For the most common workflows (dependency vulnerability check, requirement explanation, real-world triage, subdirectory scan, audit-ready report), see the prompt templates listed below in this page.

## Dependency vulnerability check

```
Check go.mod for vulnerable dependencies per PCI DSS 6.3.3. For any
HIGH or CRITICAL CVE, show the fix command and the PCI DSS remediation
SLA (30 days for HIGH).
```

Triggers `check_dependencies` against OSV.dev. Works offline against a warm `~/.pci-dss-mcp/vuln-cache/` (override via `PCI_MCP_CACHE_DIR`) if you run `update_vulnerability_db` first.

## Explain a specific requirement

```
What does PCI DSS requirement 3.3.1 mean in plain English, and what do
I need to change in a Go codebase to comply?
```

Triggers `explain_requirement` -- no scan required.

## Real-world triage / false-positive tuning

```
Run pci-dss-mcp on this project. For each HIGH and MEDIUM finding, read the
surrounding code, cross-reference with PCI DSS requirement text via
explain_requirement, and tell me whether this is a real violation or a
false positive given the architecture. For false positives, draft a
one-line pci-ignore comment with a concrete reason I can paste into
the code.
```

Use this when onboarding pci-dss-mcp to a new project. The first pass always surfaces some context-dependent FPs; this prompt makes Claude do the triage and hand you ready-to-paste suppression comments.

## Scan a subdirectory

```
Scan only ./internal/payment for PCI DSS violations. Ignore the rest of
the project.
```

pci-dss-mcp accepts any directory path -- useful for monorepos where only one package handles cardholder data.

## Audit-ready compliance report

```
Generate a PCI DSS v4.0.1 compliance report for this project in a
format I can attach to a QSA audit package. Include: per-requirement
PASS/FAIL/NOT_CHECKED status, list of findings grouped by requirement,
suppressions with reasons, and the 30/90-day remediation SLAs for each
HIGH/CRITICAL.
```

`NOT_CHECKED` requirements are not non-compliant -- they're outside the scanner's static-analysis scope and must be verified manually by a QSA.

## Suppressing findings

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

Suppressed findings appear as `SUPPRESSED` in reports, **never silently dropped**. Auditors must see what was suppressed and why.
