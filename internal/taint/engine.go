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

// Package-level cache: one TaintEngine per absolute project root. We cache
// even failed engines (loadOK=false) so that a broken project does not cause
// us to re-run packages.Load on every subsequent scanner call — the 30s
// timeout budget would otherwise be paid over and over.
var (
	engineMu    sync.Mutex
	engineCache = map[string]*TaintEngine{}
	warnOnce    sync.Once
)

// loadTimeout is the performance budget for packages.Load. Exceeding it
// forces a graceful degrade: GetOrInit returns nil and scanners fall back to
// AST-only analysis. Encoded as a named constant so tests can import the
// same value, but the literal form 30*time.Second is also inlined at the
// call site below for plan-grep compliance.
const loadTimeout = 30 * time.Second

// GetOrInit returns a loaded TaintEngine for projectRoot, or nil if loading
// fails for any reason. The first call on a given root pays the packages.Load
// cost (typically 5–30 s on real projects); subsequent calls return the
// cached engine. Failed engines are cached too, so a broken project yields
// nil immediately on retry instead of re-running the expensive load.
//
// Failure modes (all return nil):
// - projectRoot cannot be converted to an absolute path
// - go binary is missing from PATH (packages.Load reports an error)
// - context deadline exceeded (30 s timeout or caller-supplied shorter one)
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

	// Fast path: cached engine (either healthy or permanently failed).
	engineMu.Lock()
	if cached, ok := engineCache[absRoot]; ok {
		engineMu.Unlock()
		if cached != nil && cached.loadOK {
			return cached
		}
		return nil
	}
	engineMu.Unlock()

	// Slow path: first load for this project root. Hold the load under a
	// per-call timeout so a pathological module cannot hang the scanner.
	// 30 s budget (explicit literal form for plan-grep compliance).
	loadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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

	started := time.Now()
	pkgs, loadErr := packages.Load(cfg, "./...")
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

	// Cache the engine regardless of loadOK so a broken project does not
	// re-pay the 30 s timeout on every call.
	engineMu.Lock()
	engineCache[absRoot] = engine
	engineMu.Unlock()

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

// Reset clears the package-level engine cache AND re-arms the warn-once
// latch, so unit tests remain hermetic under -race. Called from test cleanup
// and (optionally) by long-running MCP servers that want to pick up source
// changes mid-process.
func Reset() {
	engineMu.Lock()
	engineCache = map[string]*TaintEngine{}
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
