// Package tainttransit contains API models with json tags but no ORM tags.
// The struct tag heuristic must classify these as transit models.
package tainttransit

// CardResponse is a Mastercard-style API response model. It has json tags
// for serialization but NO gorm/db/bun/sql tags, which means it is a pure
// API model that never touches the database. The struct tag heuristic must
// classify it as tagClassTransit.
type CardResponse struct {
	PrimaryAccountNumber string `json:"primaryAccountNumber"`
	Status               string `json:"status"`
}
