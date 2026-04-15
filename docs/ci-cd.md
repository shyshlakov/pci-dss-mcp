# CI/CD Integration

pci-dss-mcp is an MCP server using stdio transport. For CI/CD pipelines, pipe JSON-RPC messages directly to the binary.

## Basic Usage

```bash
go install github.com/shyshlakov/pci-dss-mcp@v1.0.0
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ci","version":"1.0.0"}}}' | pci-dss-mcp
```

**Pin the version.** Always use `@v1.0.0` (or a specific version), not `@latest`, to prevent supply chain substitution in CI.

## Compliance Status

The `generate_compliance_report` tool reports a compliance status:

- **PASS**: No CRITICAL, HIGH, or MEDIUM findings. LOW and INFO findings are informational only.
- **FAIL**: At least one CRITICAL, HIGH, or MEDIUM finding exists. These require action for PCI DSS compliance.

Use the compliance status line in the report output to gate your pipeline:

```bash
# Run report and check for FAIL
output=$(echo '...' | pci-dss-mcp)
if echo "$output" | grep -q "Compliance status: FAIL"; then
  echo "PCI DSS compliance check failed"
  exit 1
fi
```

## GitHub Actions Example

```yaml
name: PCI DSS Compliance
on: [pull_request]

jobs:
  pci-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'

      - name: Install pci-dss-mcp
        run: go install github.com/shyshlakov/pci-dss-mcp@v1.0.0

      - name: Run PCI DSS scan
        run: |
          # Initialize MCP session and call generate_compliance_report
          INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"ci","version":"1.0.0"}}}'
          CALL='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"generate_compliance_report","arguments":{"path":"."}}}'
          echo -e "${INIT}\n${CALL}" | pci-dss-mcp 2>/dev/null | tee report.txt
          if grep -q '"Compliance status: FAIL"' report.txt; then
            echo "::error::PCI DSS compliance check failed"
            exit 1
          fi
```

## Suppression in CI

Use `.pci-dss-mcp-ignore` to suppress known acceptable findings in CI:

```
testdata/**
internal/testutil/*.go:*
```

Place the file in the project root. It will be automatically read by `generate_compliance_report`.

Suppressed findings still appear in the report as SUPPRESSED with reason and source -- they are not silently hidden.

## Offline Dependency Scanning

The dependency scanner (`check_dependencies`) uses OSV.dev for vulnerability data. In air-gapped CI environments:

1. Pre-populate the vulnerability cache:
   ```bash
   # On a machine with internet access
   echo '{"jsonrpc":"2.0","id":1,"method":"initialize",...}
   {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"update_vulnerability_db","arguments":{}}}' | pci-dss-mcp
   ```

2. Cache the directory `~/.pci-dss-mcp/vuln-cache/` in your CI cache.

3. Set the environment variable `PCI_MCP_CACHE_DIR` to point to the cached directory:
   ```yaml
   - name: Run PCI scan (offline)
     env:
       PCI_MCP_CACHE_DIR: ${{ github.workspace }}/.vuln-cache
     run: echo '...' | pci-dss-mcp
   ```

The dependency scanner defaults to `auto` mode, which tries online first and falls back to offline cache. In a fully air-gapped environment, findings are still reported from the cached data.

## Severity and Pipeline Gating

| Severity | Pipeline Impact | Action Required |
|----------|----------------|-----------------|
| CRITICAL | Blocks pipeline | Immediate fix required |
| HIGH | Blocks pipeline | Fix before merge |
| MEDIUM | Blocks pipeline | Address in current sprint |
| LOW | Does not block | Track for documentation |
| INFO | Does not block | Informational only |

Only CRITICAL, HIGH, and MEDIUM findings cause a FAIL compliance status. LOW and INFO findings are reported but do not block the pipeline.
