# Contributing to pci-dss-mcp

Thanks for taking the time to improve this project. The notes below cover the
contribution process, development setup, and the conventions the codebase
expects from new patches.

## Reporting security vulnerabilities

**Do not open a public issue for security problems.** See
[SECURITY.md](SECURITY.md) for the private disclosure process. Public issues
are reserved for bug reports, questions, and feature discussions that do not
expose an exploit path.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/shyshlakov/pci-dss-mcp/issues) and
describe:

- What you ran (command, MCP tool name, configuration).
- What you expected to happen.
- What actually happened (full error output if any).
- Environment: OS, Go version (`go version`), and `pci-mcp --version` when
  applicable.
- A minimal reproduction if possible. For scanner false-positive or
  false-negative reports, a short Go file that triggers the behaviour is
  ideal.

For feature requests, explain the use case before the implementation. This
project maps features to PCI DSS v4.0.1 requirements, so new detectors need a
concrete requirement reference.

## Contribution process

Pull requests are the only accepted contribution channel.

1. Fork the repository and create a topic branch from `main`.
2. Make your changes on the topic branch.
3. Run the test suite locally before pushing (see below).
4. Open a pull request against `main` with a clear description of the change,
   the motivation, and the testing you performed.
5. Address review feedback with additional commits, do not force-push over
   existing review comments unless a reviewer asks you to rebase.

A single maintainer reviews contributions. Expect an initial response within
a week. Straightforward fixes are usually merged quickly; larger changes
(new scanners, new MCP tools, architectural edits) benefit from an issue
discussion first to align on scope.

## Development environment

- **Go 1.25 or newer** (see `go.mod` for the exact minimum).
- **make**, the project uses Makefile targets for every build and test task.
- **git**, commits must be signed off where required.

Clone and build:

```sh
git clone https://github.com/shyshlakov/pci-dss-mcp.git
cd pci-dss-mcp
make build
```

## Running tests

Always use the Makefile targets rather than invoking `go test` directly:

```sh
make test            # full suite under -race
make vet             # go vet
make build           # compile the binary
make test-fixture    # regression against the canonical vulnerable fixture
```

The `test-fixture` target is authoritative for detection rule changes. Any
patch that adds, removes, or reclassifies a scanner finding must update
`testdata/vulnerable-payment-service/` and `EXPECTED-FINDINGS.md` in the same
commit. The fixture cycle is RED then GREEN: update the expectation first,
confirm `make test-fixture` fails, then implement the change and confirm the
fixture passes again with no regressions.

All tests also run in CI on every pull request under `-race`, plus `go vet`,
`golangci-lint`, `govulncheck`, CodeQL, and OpenSSF Scorecard. Pull requests
cannot merge until these checks pass.

## Code style

- **Errors are never silently discarded.** `_, _ = f()` and `_ = someFunc()`
  are rejected. Return the error or log it via `slog` if the caller cannot
  handle it (for example in fire-and-forget goroutines). The single exception
  is `defer rows.Close()` after a `*sql.Rows`, where the bare defer is the
  standard Go idiom.
- **Never box typed nil pointers into `any`.** `var p *T; var x any = p`
  produces a non-nil interface because of Go's nil interface trap. Return
  concrete types or a `bool` instead.
- **Graceful degradation over hard failure.** Scanners that depend on
  external resources (the `go` binary, the network, the module cache) must
  return an empty result on failure with a single `slog.Warn`, not panic and
  not block other scanners from running.
- **Comments are reserved for non-obvious "why".** Well-named identifiers
  should explain "what". Write a comment only when a hidden constraint,
  invariant, or workaround would surprise a future reader. Comments that
  restate a function signature or describe project management context are
  removed on review.
- **No emoji** in code, comments, commit messages, or PR descriptions.
- **Table-driven tests** are the convention, one `tt := []struct{}{}` slice
  per test function with `t.Run(tt.name, ...)` subtests.

## Commit messages

Commits follow [Conventional Commits](https://www.conventionalcommits.org/)
with an optional phase or scope prefix:

```
feat(scanner): add CSP nonce verification
fix(panscanner): stop flagging masked PAN literals
docs: clarify suppression file syntax
test(auditscanner): cover method-value middleware resolution
refactor(reportscanner): extract finding filter helper
```

Use the imperative mood ("add", "fix", "update"), wrap the body at 72
characters, and explain *why* the change is needed; the *what* is already in
the diff.

## Scanner design conventions

New detection rules and scanner output changes must follow the project's
binding conventions:

- **INFO findings for verified-OK.** When a scanner detects a sensitive
  pattern *and* finds the protective measure alongside it (encryption hook,
  masking, suppression), emit an `INFO` finding rather than silently
  dropping the result. Auditors must see that the check ran.
- **Context-aware matching.** Keyword-only rules produce false positives.
  Combine keywords with context (file path, struct tags, surrounding code,
  framework detection).
- **Three-tier severity.** CRITICAL (direct violation), HIGH (potential
  violation), MEDIUM (best practice). Do not use LOW for compliance
  findings.
- **Suppression with audit trail.** `pci-ignore` comments and
  `.pci-mcp-ignore` rules do not drop findings, they emit the finding as
  `SUPPRESSED` with the reason attached so a QSA auditor can see what was
  suppressed and why.

## Running fuzz

Quick local fuzz run (default `FUZZTIME=10s` per target, ~55 seconds wall time):

```sh
make fuzz
```

The fuzz suite covers the highest-risk parsers: Luhn PAN validator, `go/ast`
source walker, base64 cursor decoder, HTML script scanner, and the go.mod /
go.sum SBOM reader. CI runs the same matrix on every PR; the nightly workflow
runs each target for 30 minutes.

## Adding a new fuzz target

pci-dss-mcp runs native Go fuzz smoke on every PR (30s/target) and a deep
nightly run (30min/target). When a new phase adds a parser, SARIF writer,
Semgrep SARIF reader, OpenAPI spec walker, or similar, the phase MUST extend
the fuzz harness. Four steps:

1. **Write the target** in a `_fuzz_test.go` file next to the code under
   test, same package. Property: the target must not panic on any byte
   input. Example:

   ```go
   func FuzzMyParser(f *testing.F) {
       f.Add([]byte(`{"valid": "seed"}`))
       f.Fuzz(func(t *testing.T, data []byte) { _, _ = ParseMyFormat(data) })
   }
   ```

2. **Seed the corpus** by committing at least 3 hand-written `f.Add` calls
   covering valid input, near-boundary edge cases, and one known-malformed
   input. For scanners that read files from disk, write a seeder script
   under `scripts/seed-fuzz-<name>.sh` that copies fixture files into
   `testdata/fuzz/FuzzMyParser/`.

3. **Wire CI.** Add a new matrix entry for your target in both
   `.github/workflows/ci.yml` (30s smoke) and
   `.github/workflows/fuzz-nightly.yml` (30min deep). Both workflows use the
   same `{name, pkg}` shape, copy an existing entry and change two strings.

4. **Add to `make fuzz`.** Append one line to the `FUZZ_TARGETS` variable in
   the Makefile: `pkg/path:FuzzMyParser`.

Smoke test locally with `make fuzz FUZZTIME=30s` before pushing. New crash
seeds discovered by the nightly run are auto-filed as GitHub issues with
reproducer bytes.

## License

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE) that covers the rest of the project.
