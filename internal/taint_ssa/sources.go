package taint_ssa

import (
	"golang.org/x/tools/go/ssa"
)

// IsPANSource reports whether v is an SSA value that reads a struct field
// whose name matches a PAN keyword. Concrete implementation is added by
// the PAN-LOGGER rule port. The Task 1 scaffold returns false so the
// public API surface is fixed before rule logic lands.
func IsPANSource(v ssa.Value) bool {
	return panSourceImpl(v)
}

// IsHardcodedKeySource reports whether v is an SSA value holding a
// hardcoded cryptographic key. Concrete implementation is added by the
// CRYPTO-HARDCODED-KEY rule port.
func IsHardcodedKeySource(v ssa.Value) bool {
	return hardcodedKeySourceImpl(v)
}

// panSourceImpl is the rule-port hook. The scaffold returns false; the
// PAN-LOGGER port replaces this body in panlogger.go via the package's
// own indirection so test files can stub recognition during development.
var panSourceImpl = func(v ssa.Value) bool { return false }

// hardcodedKeySourceImpl is the rule-port hook for crypto key recognition.
var hardcodedKeySourceImpl = func(v ssa.Value) bool { return false }
