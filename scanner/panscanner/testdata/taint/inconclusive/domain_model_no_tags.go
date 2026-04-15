// Package storage contains a domain model with no struct tags at all.
// The struct tag heuristic must return inconclusive for this struct,
// falling back to isTransitShape path-based detection.
package storage

// ProvisionTokenCard is a pure domain model with no json, gorm, db, bun,
// or sql tags. The struct tag heuristic cannot determine whether this is
// a transit or storage model, so it returns tagClassInconclusive.
type ProvisionTokenCard struct {
	CVV string
}
