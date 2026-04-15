package taint

import (
	"go/types"
)

// Source identifies a tainted value origin — a specific struct field in a
// specific package. The API lock makes this struct comparable and
// exported so scanners can build it directly without reflection.
//
// Package is the fully-qualified import path (e.g.
// TypeName is the unqualified Go type name (e.g. "TokenizeRequest").
// Field is the exported or unexported field name (e.g. "CVV").
//
// A Source that cannot be resolved in the loaded module is NOT an error
// lookupField returns nil and FlowsTo returns false. This matches the
// "unknown source" behavior required by TestFlowsTo_UnknownSource.
//
// HasJSONTag and HasDBTag are struct-level tag metadata populated by
// panscanner during the AST walk. They enable the struct
// tag heuristic in taint_bridge.go to classify transit vs storage models
// without relying on file path patterns. These fields are metadata-only
// they do NOT affect the taint engine's FlowsTo logic.
type Source struct {
	Package  string
	TypeName string
	Field    string
	// HasJSONTag is true when the enclosing struct has at least one field
	// with a `json:"..."` tag. Populated during panscanner AST walk.
	HasJSONTag bool
	// HasDBTag is true when the enclosing struct has at least one field
	// with a `gorm:"..."`, `db:"..."`, `bun:"..."`, or `sql:"..."` tag.
	HasDBTag bool
}

// lookupField resolves a Source to the concrete *types.Var for the field,
// or nil if the package / type / field is not present in the loaded module.
// Resolution is via types.Info.Scope().Lookup — no string-matching on
// selector names, because the same field on two different types must hash
// to two different objects in our taint map.
func (e *TaintEngine) lookupField(src Source) types.Object {
	if e == nil {
		return nil
	}
	pkg := findLoadedPackage(e.pkgs, src.Package)
	if pkg == nil || pkg.Types == nil {
		return nil
	}
	obj := pkg.Types.Scope().Lookup(src.TypeName)
	if obj == nil {
		return nil
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return nil
	}
	structType, ok := named.Underlying().(*types.Struct)
	if !ok {
		return nil
	}
	for i := 0; i < structType.NumFields(); i++ {
		f := structType.Field(i)
		if f.Name() == src.Field {
			return f
		}
	}
	return nil
}
