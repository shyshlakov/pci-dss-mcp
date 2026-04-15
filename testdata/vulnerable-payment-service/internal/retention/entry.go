package retention

// Invoice is a sensitive-shaped local type that pushes Z9-Z12 fixture handlers
// over the multi-signal scorer threshold via Signal 4 (sensitive-typed local
// variable). The type name is whitelisted in internal/keywords as a
// sensitive-data type; the Expiry field name is whitelisted as a
// sensitive-field name. Neither identifier trips the abstract-identifier
// gate enforced on Z9-Z12 fixture files.
type Invoice struct {
	Expiry string
}
