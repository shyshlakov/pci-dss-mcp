# cyclonedx-gomod probe notes

## Verdict

VERDICT: PLAN_B

## Evidence

Probed `github.com/CycloneDX/cyclonedx-gomod@v1.10.0` (newest patch of the v1.x line; resolved via `go get` from `v1.9.0`).

### Exported packages in cyclonedx-gomod@v1.10.0

Located via `go list -f '{{.Dir}}'` after adding blank-import probes to a throwaway module. All five public (non-`internal/`) packages:

- `github.com/CycloneDX/cyclonedx-gomod/pkg/generate` — exposes the `Generator` interface (`Generate() (*cdx.BOM, error)`)
- `github.com/CycloneDX/cyclonedx-gomod/pkg/generate/app` — `NewGenerator(moduleDir, opts...) (generate.Generator, error)` for `app` mode (build-constrained binary components)
- `github.com/CycloneDX/cyclonedx-gomod/pkg/generate/bin` — `NewGenerator(binaryPath, opts...) (generate.Generator, error)` for compiled-binary SBOMs
- `github.com/CycloneDX/cyclonedx-gomod/pkg/generate/mod` — `NewGenerator(moduleDir, opts...) (generate.Generator, error)` for `mod` mode (all required modules from go.mod); this is the candidate Phase 20 would have used
- `github.com/CycloneDX/cyclonedx-gomod/pkg/licensedetect` + `pkg/licensedetect/local` — license-detector interface and the local (go-enry-powered) detector

### Internal packages (not importable from outside cyclonedx-gomod)

The `mod.generator.Generate` implementation (verified in `pkg/generate/mod/generator.go`) imports and depends on four `internal/` packages which are therefore unreachable as building blocks from a third-party module:

- `github.com/CycloneDX/cyclonedx-gomod/internal/gocmd` — shells out to `go list -mod=readonly -json -m all`, `go env -json`, `go mod why`
- `github.com/CycloneDX/cyclonedx-gomod/internal/gomod` — owns module discovery, hashing (via `x/mod/sumdb/dirhash`), module-graph application, local-replacement resolution
- `github.com/CycloneDX/cyclonedx-gomod/internal/sbom` — dependency-graph builder for `cdx.BOM.Dependencies`
- `github.com/CycloneDX/cyclonedx-gomod/internal/sbom/convert/module` — `ToComponent` / `ToComponents` (module-to-cdx.Component translation, hash extraction, purl/license attachment)

These internals are the real worker logic; `pkg/generate/mod` is a thin functional-options wrapper around them.

### Candidate API signatures (exported)

Taken from `pkg/generate/mod/generator.go` and `pkg/generate/mod/options.go`:

- `mod.NewGenerator(moduleDir string, opts ...mod.Option) (generate.Generator, error)` — constructs the mod-mode BOM generator
- `(generate.Generator).Generate() (*cdx.BOM, error)` — produces the BOM; internally runs `go mod why`, then `go list -json -m all` (or vendor enumeration), then `gomod.ApplyModuleGraph` (more `go mod graph` shell-outs)
- `mod.WithComponentType(cdx.ComponentType) mod.Option`
- `mod.WithIncludeStdlib(bool) mod.Option`
- `mod.WithIncludeTestModules(bool) mod.Option`
- `mod.WithLicenseDetector(licensedetect.Detector) mod.Option`
- `mod.WithLogger(zerolog.Logger) mod.Option`
- `mod.WithShortPURLS(bool) mod.Option`
- `licensedetect.Detector` (interface) — the only way to plug license detection; the `local.NewDetector()` implementation transitively depends on `github.com/go-enry/go-license-detector/v4`

## Decision

PLAN_B wins on three independent grounds:

1. **R-03 offline contract violation (hard block).** `mod.generator.Generate` calls `gomod.LoadModules` → `gocmd.ListModules` → `exec.Command("go", "list", "-mod=readonly", "-json", "-m", "all")`. With `GOPROXY=off` and an empty `GOMODCACHE`, `go list -m all` fails because it cannot resolve transitive requires from local files alone (unlike `go list -m` without `all`, which only needs go.mod). Our R-03 acceptance test pins `GOPROXY=off` and seeds an empty `GOMODCACHE` — the library path would error out where the plan-B path succeeds (plan-B reads go.mod/go.sum directly with `modfile.ParseLax` and only probes `$GOMODCACHE/<mod>@<ver>/` for licenses).

2. **Transitive-dependency blast radius (quality gate).** `go mod tidy` on a probe module that imports `pkg/generate/mod` + `pkg/licensedetect/local` pulled in **42 indirect dependencies**: `go-git/go-git/v5`, `ProtonMail/go-crypto`, `go-enry/go-license-detector/v4` (which in turn drags in `jdkato/prose`, `neurosnap/sentences.v1`, `dgryski/go-minhash`, `ekzhu/minhash-lsh`, `shogo82148/go-shuffle`, `gonum.org/v1/gonum`, `montanaflynn/stats`, `russross/blackfriday/v2`, `hhatto/gorst`, `terminalstatic/go-xsd-validate`, `shurcooL/sanitized_anchor_name`), `rs/zerolog`, `cloudflare/circl`, `pjbgf/sha1cd`, `emirpasic/gods`, `cyphar/filepath-securejoin`, and more. That is a supply-chain surface expansion of roughly 40x vs plan-B (plan-B adds only `cyclonedx-go` — zero indirect deps beyond what the project already carries). For a *PCI-DSS* compliance tool, shipping a go-git+NLP+graph-stats dependency graph is operationally and reviewably hostile.

3. **Internal-package lock-in (R-02 branch-point criterion).** CONTEXT R-02 explicitly warned this was likely: "most packages are under internal/". Confirmed — the actual module-discovery, hashing, and component-translation logic (`internal/gomod`, `internal/sbom/convert/module`) is not importable. We could only call `Generate()` as a black box; we cannot reuse its hash or purl helpers piecewise. This means no clean way to implement cache-miss `UNKNOWN-LICENSE` fallback without patching upstream.

Plan-B reuses battle-tested primitives already in the project (`golang.org/x/mod/modfile` is already a direct dep of pci-dss-mcp via depscanner/Phase 8), decodes go.sum `h1:` hashes in 20 lines, constructs PURLs with `fmt.Sprintf`, and probes `GOMODCACHE` with `os.Stat`. It honors the R-03 offline contract by construction — no `go` binary, no network, only file I/O.

## Task 2 usage sketch

```go
package sbomscanner

import (
    "context"
    "fmt"

    cdx "github.com/CycloneDX/cyclonedx-go"
)

func GenerateSBOM(ctx context.Context, projectDir string) (*SBOM, error) {
    if err := ctx.Err(); err != nil {
        return nil, err
    }
    mods, err := listModules(projectDir) // discovery.go: modfile.ParseLax + go.sum map
    if err != nil {
        return nil, fmt.Errorf("sbom discovery: %w", err)
    }
    bom := cdx.NewBOM()
    bom.SpecVersion = cdx.SpecVersion1_5
    components := make([]cdx.Component, 0, len(mods))
    for _, m := range mods {
        c := cdx.Component{
            Type:       cdx.ComponentTypeLibrary,
            Name:       m.Path,
            Version:    m.Version,
            PackageURL: buildPURL(m.Path, m.Version),
        }
        if hex, hErr := hashFromH1Sum(m.Sum); hErr == nil {
            c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: hex}}
        }
        if lic := readLicense(m.Path, m.Version); lic == "UNKNOWN-LICENSE" {
            c.Properties = &[]cdx.Property{{Name: "UNKNOWN-LICENSE", Value: "cache-miss or unreadable"}}
        } else {
            c.Licenses = &cdx.Licenses{{License: &cdx.License{ID: lic}}}
        }
        components = append(components, c)
    }
    bom.Components = &components
    return convertBOM(bom), nil // convertBOM shims cdx.BOM -> local SBOM shape consumed by fixture_test
}
```

## Dependencies task 2 must add

PLAN_B keeps the dependency footprint minimal:

- `github.com/CycloneDX/cyclonedx-go v0.9.3` — data model only (`cdx.BOM`, `cdx.Component`, `cdx.Hash`, `cdx.Licenses`, serializers). Zero indirect dependencies beyond `github.com/google/jsonschema-go` which pci-dss-mcp already ships. Pinned to the version resolved during the probe round.

Not added (would be required for LIBRARY_PATH): `github.com/CycloneDX/cyclonedx-gomod`, `github.com/go-enry/go-license-detector/v4`, `github.com/go-git/go-git/v5`, `github.com/rs/zerolog`, and their ~40 transitives.
