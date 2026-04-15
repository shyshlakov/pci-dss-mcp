package taint

import (
	"go/types"
	"sync"

	"golang.org/x/tools/go/packages"
)

// SinkKind enumerates the dangerous-operation categories the taint engine
// can match. ships two real kinds (SinkDBStore, SinkHTTPClient) and
// three stubs (SinkHTTPResponse, SinkLoggerCall, SinkCryptoCall) so
// later plans can plug in without an API break.
type SinkKind int

const (
	SinkDBStore      SinkKind = iota // database/sql, gorm, redis, sqlx writes
	SinkHTTPClient                   // net/http.Client outbound calls
	SinkHTTPResponse                 //  stub (ERR-LEAK bridge later)
	SinkLoggerCall                   //  stub (PAN-LOGGER bridge later)
	SinkCryptoCall                   //  stub (CRYPTO-HARDCODED-KEY later)
)

// SinkPattern describes a FlowsTo query: what kind of sink we are checking
// against and (optionally) which importer package paths to restrict to. A
// zero-value Packages slice means "any package in the loaded module".
type SinkPattern struct {
	Kind     SinkKind
	Packages []string
}

// sinkTarget is a resolved sink — a specific *types.Func plus a debug name
// for logging. Resolution is by pointer identity: two method call sites that
// reach the same (*gorm.DB).Create must yield the same *types.Func, and that
// pointer is what we compare against at every CallExpr.
type sinkTarget struct {
	Func *types.Func
	Name string
}

// sinkSpec is a human-readable description of a single sink method. The
// resolver turns specs into sinkTargets at first FlowsTo call.
type sinkSpec struct {
	PkgPath  string
	TypeName string
	Method   string
}

// sinkLibrary is the baked-in sink database for. Two real kinds
// three stubs. See / Pattern 3 for the
// rationale behind each entry. Redis v8 and v9 are both listed because
var sinkLibrary = map[SinkKind][]sinkSpec{
	SinkDBStore: {
		{"gorm.io/gorm", "DB", "Create"},
		{"gorm.io/gorm", "DB", "Save"},
		{"gorm.io/gorm", "DB", "Updates"},
		{"gorm.io/gorm", "DB", "FirstOrCreate"},
		{"gorm.io/gorm", "DB", "Exec"},
		{"database/sql", "DB", "Exec"},
		{"database/sql", "DB", "ExecContext"},
		{"database/sql", "Tx", "Exec"},
		{"database/sql", "Tx", "ExecContext"},
		{"database/sql", "Stmt", "Exec"},
		{"database/sql", "Stmt", "ExecContext"},
		{"github.com/redis/go-redis/v9", "Client", "Set"},
		{"github.com/redis/go-redis/v8", "Client", "Set"},
		{"github.com/go-redis/redis/v9", "Client", "Set"},
		{"github.com/go-redis/redis/v8", "Client", "Set"},
		{"github.com/jmoiron/sqlx", "DB", "Exec"},
		{"github.com/jmoiron/sqlx", "DB", "NamedExec"},
	},
	SinkHTTPClient: {
		{"net/http", "Client", "Do"},
		{"net/http", "Client", "Post"},
		{"net/http", "Client", "PostForm"},
		{"net/http", "Client", "Get"},
	},
	SinkHTTPResponse: nil, //  stub
	SinkLoggerCall:   nil, //  stub
	SinkCryptoCall:   nil, //  stub
}

// resolveSinks turns a SinkPattern into the concrete *types.Func targets
// present in the current loaded module. Resolution is lazy (on first use per
// kind) and cached on the engine. Missing packages (e.g. a project that does
// not import gorm) are silently tolerated — the spec simply contributes
// zero targets.
//
// Concurrency: protected by e.loadMu so two scanners calling FlowsTo in
// parallel cannot double-resolve the same kind.
func (e *TaintEngine) resolveSinks(pattern SinkPattern) []sinkTarget {
	if e == nil || !e.loadOK {
		return nil
	}
	e.loadMu.Lock()
	defer e.loadMu.Unlock()

	if cached, ok := e.sinkObjects[pattern.Kind]; ok {
		return filterByPackages(cached, pattern.Packages)
	}

	specs := sinkLibrary[pattern.Kind]
	if len(specs) == 0 {
		e.sinkObjects[pattern.Kind] = nil
		return nil
	}

	var targets []sinkTarget
	for _, spec := range specs {
		pkg := findLoadedPackage(e.pkgs, spec.PkgPath)
		if pkg == nil || pkg.Types == nil {
			continue
		}
		obj := pkg.Types.Scope().Lookup(spec.TypeName)
		if obj == nil {
			continue
		}
		named, ok := obj.Type().(*types.Named)
		if !ok {
			continue
		}

		// A2 / RESEARCH §Pitfall 6: walk the pointer method set so embedded
		// and promoted methods on *T are reachable. Value-receiver methods
		// are also included by pointer method-set promotion rules, so a
		// single NewMethodSet on *T is sufficient to see both receiver kinds.
		mset := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < mset.Len(); i++ {
			sel := mset.At(i)
			fn, ok := sel.Obj().(*types.Func)
			if !ok {
				continue
			}
			if fn.Name() != spec.Method {
				continue
			}
			targets = append(targets, sinkTarget{
				Func: fn,
				Name: spec.PkgPath + "." + spec.TypeName + "." + spec.Method,
			})
		}
	}

	e.sinkObjects[pattern.Kind] = targets
	return filterByPackages(targets, pattern.Packages)
}

// filterByPackages applies the optional Packages restriction on a pattern.
// An empty allowlist means "any package is acceptable".
func filterByPackages(targets []sinkTarget, allow []string) []sinkTarget {
	if len(allow) == 0 {
		return targets
	}
	lookup := map[string]bool{}
	for _, a := range allow {
		lookup[a] = true
	}
	var out []sinkTarget
	for _, t := range targets {
		if t.Func == nil || t.Func.Pkg() == nil {
			continue
		}
		if lookup[t.Func.Pkg().Path()] {
			out = append(out, t)
		}
	}
	return out
}

// findLoadedPackage walks the packages.Package slice — including their
// transitive Imports map — looking for importPath. This is necessary because
// packages.Load("./...") only returns the root packages of the target
// module; sinks like "database/sql" live deep in the dependency graph and
// must be reached via Imports.
//
// Uses a seen map to avoid pathological cycles in complex dependency graphs.
func findLoadedPackage(pkgs []*packages.Package, importPath string) *packages.Package {
	if importPath == "" {
		return nil
	}
	seen := map[string]bool{}
	var visit func(*packages.Package) *packages.Package
	visit = func(p *packages.Package) *packages.Package {
		if p == nil || seen[p.PkgPath] {
			return nil
		}
		seen[p.PkgPath] = true
		if p.PkgPath == importPath {
			return p
		}
		for _, imp := range p.Imports {
			if match := visit(imp); match != nil {
				return match
			}
		}
		return nil
	}
	for _, p := range pkgs {
		if match := visit(p); match != nil {
			return match
		}
	}
	return nil
}

// sinksByFunc is a constant-time lookup helper used inside the propagation
// loop. It turns the []sinkTarget slice into a set keyed by *types.Func for
// R5 ("sink hit") checks.
func sinksByFunc(targets []sinkTarget) map[*types.Func]bool {
	out := make(map[*types.Func]bool, len(targets))
	for _, t := range targets {
		if t.Func != nil {
			out[t.Func] = true
		}
	}
	return out
}

// Make sure sync.Once is referenced so go vet does not complain about
// the unused import sync when propagate.go evolves. This is a trivial stub;
// it is exercised indirectly by resolveSinks's loadMu.
var _ sync.Once
