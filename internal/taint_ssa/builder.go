// Package taint_ssa is a research-only PoC that ports two PCI DSS detection
// rules (PAN-LOGGER, CRYPTO-HARDCODED-KEY) from the existing AST taint engine
// in internal/taint to an SSA-based engine built on
// golang.org/x/tools/go/ssa. The package exists to capture side-by-side
// recall, precision, wall-clock, and memory metrics so a fork-in-the-road
// engine decision can be made with data.
//
// Per phase 21 plan 04 design constraint, NO production code path imports
// this package. Scanners do NOT consume taint_ssa APIs in this phase or
// any subsequent phase unless an explicit decision document recommends
// migration. The package compiles standalone and tests run standalone.
package taint_ssa

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// buildTimeout bounds SSA construction. SSA build is more expensive than the
// AST-only packages.Load used by internal/taint (which uses 90s) because
// CreatePackage and Build run extra work to materialize the IR. 60s is
// sufficient for the bounded fixture testdata/vulnerable-payment-service;
// real-world projects may need a longer budget when the engine ships.
const buildTimeout = 60 * time.Second

type Program struct {
	Prog *ssa.Program
	Pkgs []*ssa.Package
	Fset *FileSet
}

// FileSet wraps token.FileSet via the program's own Fset. We expose it as a
// minimal interface so callers do not need to import go/token directly.
type FileSet = ssa.Program

func BuildProgram(ctx context.Context, projectRoot string) (*Program, error) {
	if projectRoot == "" {
		return nil, errors.New("projectRoot is empty")
	}
	absRoot, err := filepath.Abs(filepath.Clean(projectRoot))
	if err != nil {
		return nil, fmt.Errorf("resolve project root: %w", err)
	}

	loadCtx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()

	cfg := &packages.Config{
		Context: loadCtx,
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps |
			packages.NeedImports,
		Dir:   absRoot,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("packages.Load: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, errors.New("no packages loaded")
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, errors.New("packages load reported errors")
	}

	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.BuilderMode(0))
	if prog == nil {
		return nil, errors.New("ssautil.Packages returned nil program")
	}
	prog.Build()

	return &Program{
		Prog: prog,
		Pkgs: ssaPkgs,
		Fset: prog,
	}, nil
}

func (p *Program) Functions() []*ssa.Function {
	if p == nil || p.Prog == nil {
		return nil
	}
	var out []*ssa.Function
	for _, pkg := range p.Pkgs {
		if pkg == nil {
			continue
		}
		for _, member := range pkg.Members {
			if fn, ok := member.(*ssa.Function); ok {
				out = append(out, fn)
				out = append(out, anonymousFunctions(fn)...)
			}
		}
	}
	return out
}

func anonymousFunctions(parent *ssa.Function) []*ssa.Function {
	var out []*ssa.Function
	for _, anon := range parent.AnonFuncs {
		out = append(out, anon)
		out = append(out, anonymousFunctions(anon)...)
	}
	return out
}

func (p *Program) PackageByPath(path string) *ssa.Package {
	if p == nil {
		return nil
	}
	for _, pkg := range p.Pkgs {
		if pkg == nil {
			continue
		}
		if pkg.Pkg != nil && pkg.Pkg.Path() == path {
			return pkg
		}
	}
	return nil
}
