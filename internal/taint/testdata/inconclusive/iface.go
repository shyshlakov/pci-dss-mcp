package inconclusive

// Req is the taint source — its CVV field is passed through an interface
// dispatch site, which the an earlier release engine cannot resolve statically. The
// test asserts FlowsTo terminates and returns false without panic.
type Req struct {
	CVV string
}

// Tokenizer is a vtable — no concrete implementation exists in this module,
// so resolveCallee returns nil for t.Tokenize and the trace stops.
type Tokenizer interface {
	Tokenize(r Req)
}

// Run is the inconclusive call site.
func Run(t Tokenizer, r Req) {
	t.Tokenize(r)
}
