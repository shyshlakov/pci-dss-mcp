// Package storage holds a CHD field in a path that does NOT match any
// transit shape (no /requests/, /responses/, /dto/, /api/, /client/,
// /handler/ markers). The taint engine cannot find a DB sink either,
// because no Save function is wired up. The bridge must keep the existing
// HIGH severity per D-06c row 3 ("inconclusive — keep severity").
package storage

// Card is a CHD-bearing struct in a non-transit-shape path. No call site
// reaches a DB sink in this fixture, but the bridge must NOT downgrade.
//
// PrimaryAccountNumber is a PAN-keyword field that is deliberately EXCLUDED
// from an earlier release negative evidence heuristic (PAN CAN be legitimately
// stored per PCI DSS 3.5.1). Therefore the decision chain falls through to
// isTransitShape → path does not match → severity is preserved.
type Card struct {
	PrimaryAccountNumber string
}
