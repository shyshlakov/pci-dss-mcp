package storedmodel

// Card is a persistent domain model — the Number and CVV fields DO flow to
// a database/sql sink via Save below, so FlowsTo(SinkDBStore) must return
// true for both fields (the stored / HIGH path in D-06c).
type Card struct {
	Number string
	CVV    string
}
