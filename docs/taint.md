# Taint Analysis

pci-dss-mcp implements flow-based severity adjustment via `go/packages` type-aware analysis in the [`internal/taint`](../internal/taint) package. When enabled, the PAN scanner distinguishes cardholder data in transit (request DTOs, API client models) from cardholder data at rest (DB models), downgrading false-positive HIGH findings on transit fields to INFO and suppressing `PAN-TYPE` findings entirely per the PCI SSC FAQ on non-persistent memory encryption.

## Enabling

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

## Performance cost

Taint analysis loads the full Go module via `go/packages`, which takes **5-30 seconds** depending on module size and transitive dependency count. A 30-second hard ceiling is enforced; on timeout, the scanner falls back to AST-only analysis with a warning logged to stderr (graceful degradation).

## Requirements

- `go` binary on `PATH` (checked by `go version`)
- Target project must type-check cleanly (no missing imports, no syntax errors)
- Module cache pre-populated if running offline -- `go list` may fetch from `GOPROXY`

## Hardening recommendation

When running taint analysis on untrusted project paths (for example in CI against third-party code), set `GOFLAGS=-mod=readonly` to prevent `go list` from fetching modules from attacker-controlled proxies:

```bash
GOFLAGS=-mod=readonly pci-dss-mcp
```

## What taint analysis does

| Rule | Without taint | With `include_taint=true` |
|------|---------------|---------------------------|
| `PAN-KEYWORD` on CVV/PAN struct field | HIGH (unconditional) | HIGH if field flows to DB storage sink; INFO if transit-only (DTO, API client); HIGH if inconclusive |
| `PAN-TYPE` on `string` CHD field | MEDIUM (unconditional) | MEDIUM if field flows to DB storage sink; **suppressed entirely** if transit-only per PCI SSC FAQ |
| `ERR-LEAK` | unchanged | unchanged |
| `PAN-LOGGER` | unchanged | unchanged |

See also [Taint Scoping](scoping.md) for when to use taint ON vs fast mode.
