// Package delegation verifies that authscanner skips MFA checks on
// wrapper handlers whose body is a single delegating call. B-12 fixture.
package delegation

import "net/http"

// Wrapper is a CHD-scoped delegation handler. Its package path contains
// a tokens segment so the multi-signal scorer admits the function for
// MFA analysis. This shape previously tripped AUTH-MISSING-MFA because
// the scanner could not see that the embedded DispatchRouter owns the
// real middleware. B-12 fix skips single-statement delegation bodies.
type Wrapper struct {
	inner DispatchRouter
}

// ServeHTTP delegates every request to the inner router. This is the
// shape B-12 must NOT flag once the scanner fix lands. Body is a single
// statement invoking the inner router's ServeHTTP.
func (x *Wrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	x.inner.ServeHTTP(w, r)
}
