// Package taint is the type-aware data-flow analysis engine for the PCI-MCP
// compliance scanner. It answers a single question per query:
//
//	"Does this struct field flow to a dangerous sink?"
//
// The engine loads a Go module once per scan session via
// golang.org/x/tools/go/packages, caches it in a package-level engineCache
// keyed by the absolute project root, and gracefully degrades to nil on every
// failure mode (missing "go" binary, packages.Load timeout, root-level
// typecheck errors, bad path).
//
// This package is infrastructure — it knows NOTHING about PCI DSS rules.
// Scanners that want flow information call into TaintEngine.FlowsTo from
// their pattern-match path; on nil they fall back to existing AST-only
// behavior. Integration helpers live in integration.go.
//
// decisions honored here:
// -: taint is in its own package, separate from scanners
// -: lazy loading; first GetOrInit triggers packages.Load
// -: exact Mode bits (NeedName|NeedFiles|NeedSyntax|NeedTypes|NeedTypesInfo|NeedDeps)
// -: locked public API — GetOrInit, FlowsTo, Reset, Source, SinkPattern
// -: graceful degradation, single slog.Warn via sync.Once
// -: 30-second context timeout per packages.Load call
//
// Security mitigations:
// - filepath.Clean + filepath.Abs sanitize the projectRoot argument
// before it ever reaches packages.Config.Dir or the cache key.
// - the 30s context.WithTimeout bounds packages.Load; on degrade a
// failed engine is cached so repeated calls do not re-explode the budget.
package taint

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"
)

// TaintEngine holds a single loaded Go module with type information and a
// lazily resolved sink library. Instances are shared across scanners for the
// duration of one scan session and are mutated only under loadMu.
type TaintEngine struct {
	pkgs        []*packages.Package
	root        string
	loadOK      bool
	loadMu      sync.Mutex
	sinkObjects map[SinkKind][]sinkTarget
}

// loadEntry serializes concurrent GetOrInit callers for the same projectRoot
// behind a sync.Once. Without this, parallel test goroutines that hit the
// same root race past the cache check, fire packages.Load N times in
// parallel, saturate x/tools' GOMAXPROCS-bounded cpuLimit semaphore, and
// deadlock on the bounded chan-send in parseFile (packages.go:1377). One
// timed-out Load leaks a goroutine that holds a cpuLimit slot forever; N
// concurrent timed-out Loads compound until subsequent Load calls hang
// forever waiting for the never-released slots.
type loadEntry struct {
	once   sync.Once
	engine *TaintEngine // nil for failed loads; set inside once.Do
}

// Package-level cache: one loadEntry per absolute project root. The entry
// is created on first request and the underlying engine is built exactly
// once via entry.once.Do regardless of caller concurrency. Failed engines
// keep the entry with engine=nil so a broken project does not re-pay the
// 90 s timeout on every call.
var (
	engineMu    sync.Mutex
	engineCache = map[string]*loadEntry{}
	warnOnce    sync.Once
)

// loadTimeout is the performance budget for packages.Load. Exceeding it
// forces a graceful degrade: GetOrInit returns nil and scanners fall back to
// AST-only analysis. Bumped 30s -> 90s after GitHub Actions migrated
// macos-latest to macOS 15 arm64 runners (3 vCPU / 7 GB RAM) in Aug-Sep 2025,
// where go/packages.Load under -race stalls past 30s on the vulnerable-payment-service
// fixture. ubuntu-latest (4 vCPU / 16 GB) still fits well under the new budget.
const loadTimeout = 90 * time.Second

// GetOrInit returns a loaded TaintEngine for projectRoot, or nil if loading
// fails for any reason. The first call on a given root pays the packages.Load
// cost (typically 5–30 s on real projects); subsequent calls return the
// cached engine. Failed engines are cached too, so a broken project yields
// nil immediately on retry instead of re-running the expensive load.
//
// Failure modes (all return nil):
// - projectRoot cannot be converted to an absolute path
// - go binary is missing from PATH (packages.Load reports an error)
// - context deadline exceeded (90 s timeout or caller-supplied shorter one)
// - root-level packages have no TypesInfo (hard typecheck failure)
//
// On the first degrade in a process, we emit exactly one slog.Warn record
// via sync.Once so real servers do not spam operators on every request.
func GetOrInit(ctx context.Context, projectRoot string) *TaintEngine {
	// Sanitize the untrusted path before caching or loading.
	absRoot, err := filepath.Abs(filepath.Clean(projectRoot))
	if err != nil {
		warnOnce.Do(func() {
			slog.Warn("taint analysis unavailable",
				"reason", "invalid project root",
				"root", projectRoot,
				"err", err.Error())
		})
		return nil
	}

	// Get-or-create the per-root load entry under engineMu. Concurrent callers
	// for the same absRoot share one entry and serialize on entry.once,
	// preventing thundering-herd packages.Load calls that would race the
	// global x/tools cpuLimit semaphore.
	engineMu.Lock()
	entry, ok := engineCache[absRoot]
	if !ok {
		entry = &loadEntry{}
		engineCache[absRoot] = entry
	}
	engineMu.Unlock()

	entry.once.Do(func() {
		entry.engine = doLoad(ctx, absRoot)
	})

	return entry.engine
}

// doLoad runs the slow-path packages.Load under a 90 s timeout. Returns a
// healthy *TaintEngine, or nil for any failure mode. Called exactly once per
// projectRoot via the loadEntry sync.Once.
func doLoad(ctx context.Context, absRoot string) *TaintEngine {
	loadCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	_ = loadTimeout // keep the named constant referenced for future callers
	defer cancel()

	cfg := &packages.Config{
		Context: loadCtx,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports,
		Dir:   absRoot,
		Tests: false,
	}

	// Wrap packages.Load in a goroutine + select so the 90 s loadCtx actually
	// returns control to the caller. Context alone is insufficient because
	// x/tools' parseFiles errgroup workers block on a bounded cpuLimit channel
	// (packages.go:1377) that does not honor ctx.Done, so on a recursive-parse
	// deadlock the Load call never returns even after cancel(). We accept a
	// worker-goroutine leak as the cost of guaranteed bounded scanner latency.
	// The sync.Once-per-root in GetOrInit prevents this leak from compounding
	// across concurrent callers for the same root.
	type loadResult struct {
		pkgs []*packages.Package
		err  error
	}
	resultCh := make(chan loadResult, 1)
	started := time.Now()
	go func() {
		pkgs, err := packages.Load(cfg, "./...")
		resultCh <- loadResult{pkgs: pkgs, err: err}
	}()

	var (
		pkgs    []*packages.Package
		loadErr error
	)
	select {
	case r := <-resultCh:
		pkgs, loadErr = r.pkgs, r.err
	case <-loadCtx.Done():
		loadErr = loadCtx.Err()
	}
	elapsed := time.Since(started)

	engine := &TaintEngine{
		pkgs:        pkgs,
		root:        absRoot,
		sinkObjects: map[SinkKind][]sinkTarget{},
	}

	// A successful load is (a) no Go-level error from packages.Load itself
	// and (b) no package with nil Types/TypesInfo — the latter signals a hard
	// typecheck failure that would make propagation unreliable.
	engine.loadOK = loadErr == nil && len(pkgs) > 0 && !containsHardErrors(pkgs)

	if !engine.loadOK {
		reason := "typecheck errors"
		if loadErr != nil {
			reason = loadErr.Error()
		} else if len(pkgs) == 0 {
			reason = "no packages loaded"
		}
		warnOnce.Do(func() {
			slog.Warn("taint analysis unavailable",
				"reason", reason,
				"root", absRoot,
				"duration_ms", elapsed.Milliseconds())
		})
		return nil
	}

	slog.Info("taint engine loaded",
		"packages", len(pkgs),
		"root", absRoot,
		"duration_ms", elapsed.Milliseconds())
	return engine
}

// LoadedPackages returns the loaded *packages.Package slice for callers that
// need to walk typed AST themselves (e.g. scanner/httpinputscanner intra-procedural
// USER_INPUT analysis). Returns nil when the engine is nil or load failed so
// callers can fall back without panicking.
func (e *TaintEngine) LoadedPackages() []*packages.Package {
	if e == nil || !e.loadOK {
		return nil
	}
	return e.pkgs
}

// LookupLoadedPackage returns the loaded *packages.Package for importPath, or
// nil when the engine has not loaded that package. Walks the same Imports
// closure as the internal sink resolver.
func (e *TaintEngine) LookupLoadedPackage(importPath string) *packages.Package {
	if e == nil || !e.loadOK {
		return nil
	}
	return findLoadedPackage(e.pkgs, importPath)
}

// Reset clears the package-level engine cache AND re-arms the warn-once
// latch, so unit tests remain hermetic under -race. Called from test cleanup
// and (optionally) by long-running MCP servers that want to pick up source
// changes mid-process.
func Reset() {
	engineMu.Lock()
	engineCache = map[string]*loadEntry{}
	warnOnce = sync.Once{}
	engineMu.Unlock()
}

// containsHardErrors reports whether any of the loaded root packages fail
// the "healthy load" bar:
//
// - Types or TypesInfo is nil (type checker never ran), OR
// - The package has at least one packages.TypeError or packages.ParseError
// (hard errors that will make propagation unreliable).
//
// Missing-import list errors in deep transitive deps are tolerated — they do
// not poison the loaded root packages' type information.
//
// TODO: allow partial loads where some files typecheck and some do not,
// by filtering e.pkgs to only the healthy subset.
func containsHardErrors(pkgs []*packages.Package) bool {
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		if p.Types == nil || p.TypesInfo == nil {
			return true
		}
		for _, perr := range p.Errors {
			if perr.Kind == packages.TypeError || perr.Kind == packages.ParseError {
				return true
			}
		}
	}
	return false
}
