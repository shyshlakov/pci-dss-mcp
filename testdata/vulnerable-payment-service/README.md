# Vulnerable Payment Service Fixture

A deliberately-insecure mock payment service used as the canonical regression
benchmark for the [pci-dss-mcp](../../README.md) PCI DSS v4.0.1 compliance scanner.

## Status

Fixture covers ~52 intentional violations across 55 production scanner rules
plus ~12 clean counter-examples, wired to the acceptance test.

## Purpose

1. **Public reproducibility** — any contributor can clone the repo and run
   the scanner end-to-end without access to private payment codebases.
2. **Stable baseline** — unlike real-world projects that shift as teams fix
   findings, this fixture is pinned so regressions surface immediately.
3. **Regression suite** — every future feature (SBOM, govulncheck,
   SARIF, Semgrep adapter, cross-service CHD flow) must update this
   fixture as a TDD step (RED before GREEN).
4. **Living documentation** — users run the scanner on this module and see
   every violation type in action with file:line references and requirement
   mappings.
5. **QSA demo** — "run this, see what we detect" is a stronger artifact than
   prose descriptions.

## How to scan

Once the root binary is built, point `generate_compliance_report` at this
directory. Taint analysis is recommended so the stored-vs-transit CHD
classification matches the fixture's intent:

```
./pci-dss-mcp generate_compliance_report testdata/vulnerable-payment-service --include_taint=true
```

Shorthand Makefile targets from the repo root:

```
make build-fixture   # go build ./... inside the fixture module
make test-fixture    # go test ./... inside the fixture (+ root acceptance test)
make scan-fixture    # builds pci-dss-mcp and scans the fixture directory
```

The authoritative list of expected findings lives in
`EXPECTED-FINDINGS.md`.

## How to add new violations (TDD workflow)

Every change that introduces a new detection rule or output format
MUST follow this cycle:

1. **RED** — add the new violating (or positive) pattern to this fixture.
   Update `EXPECTED-FINDINGS.md` with the expected rule ID, file:line,
   and severity. Run `make test-fixture` — it must fail with "expected
   finding missing" or "unexpected finding present".
2. **GREEN** — implement the scanner/format change in the main module.
   Run `make test-fixture` again — it must pass with zero regressions
   on previously-expected findings.
3. **REFACTOR** — clean up. The fixture acceptance test remains green.

## Structure

```
cmd/server/               -- gin entry point + blank go-jose reference
internal/http/middleware/ -- RequestLogger, Recovery, RequireMFA, constants
internal/http/handler/    -- Wave 2 populates tokens/admin/checkout/callback
```

Wave 2 additions (not yet present on this branch):

```
internal/auth/            -- hardcoded pwd, weak policy, MFA skip
internal/crypto/          -- md5, hardcoded AES key
internal/cache/           -- redis no-TTL / keep-TTL / no-expire variants
internal/http/legacy_client.go -- TLS 1.0, weak cipher
internal/service/tokens/  -- service-layer PAN logging, tag-less model
internal/storage/postgres/{model,migrations}/ -- gorm + SQL cross-ref
internal/test/            -- dev-context markers, fixture test helpers
internal/util/             -- zeroing variants (before-auth, defer-only, ...)
pkg/{visa,mastercard}/    -- TLS clients, API DTOs
configs/                   -- env/yaml/toml secrets + retention TTL gaps
templates/                 -- HTML CSP/SRI/nonce/FIM scenarios
```

## DISCLAIMER

This code is intentionally vulnerable to exercise static analysis rules for
PCI DSS v4.0.1. **DO NOT deploy to production**. **DO NOT copy these patterns
into real payment services**. The fixture includes hardcoded credentials,
weak crypto, plain-HTTP payment calls, unsanitized error output, missing
audit logging, and a pinned vulnerable go-jose release. It exists solely as
a negative test corpus for the scanner and must never be imported, executed,
or referenced by production code.
