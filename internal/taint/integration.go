package taint

import "context"

// IsTransit returns true when the given Source is confirmed to NOT flow to
// any database storage sink. It is a thin convenience wrapper used by the
// panscanner taint bridge in and by future transit-vs-stored
// downgrades in Plans 18b / 19.
//
// Semantics:
// - engine unavailable (nil) → false (inconclusive; scanner keeps its
// current severity)
// - flow confirmed to DB sink → false (definitely stored)
// - flow NOT found to any DB sink → true (transit-only)
//
// The "engine unavailable → false" branch deliberately matches current
// scanner behavior: with no flow info we cannot prove transit, so we must
// fall back to the original (possibly over-flagged) severity.
func IsTransit(ctx context.Context, projectRoot string, src Source) bool {
	engine := GetOrInit(ctx, projectRoot)
	if engine == nil {
		return false
	}
	return !engine.FlowsTo(src, SinkPattern{Kind: SinkDBStore})
}
