package taint

import (
	"go/ast"
	"go/types"
)

// propagateUserInput is the dispatcher for D-13 taint propagator rules
// (fmt.Sprintf family, fmt.Errorf %w, errors wrap libraries, multierror,
// context.WithValue, recover, type conversions, gin.Context.Set/Get).
//
// Task 2 lands a stub returning false (no propagation handled) so the source
// recognition path compiles standalone; Task 3 fills in the propagator
// catalog. Returning true means "this call expression has been fully handled
// by USER_INPUT propagation and the caller may skip default processing".
func propagateUserInput(call *ast.CallExpr, info *types.Info, state *flowState) (handled bool) {
	_ = call
	_ = info
	_ = state
	return false
}
