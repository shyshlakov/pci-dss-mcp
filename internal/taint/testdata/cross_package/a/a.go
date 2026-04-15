package a

// Req lives in package a — its PAN field is the taint source for the
// cross-package resolution test. See ../b/b.go for the downstream sink.
type Req struct {
	PAN string
}
