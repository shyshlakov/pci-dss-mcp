// Package storedmodel persists Card data into a database/sql sink. The
// taint engine must report FlowsTo(SinkDBStore) = true for both CardNumber
// and CVV, so the bridge keeps PAN-KEYWORD at HIGH and annotates the
// description with "flows to DB storage sink".
package storedmodel

import "database/sql"

// Card is a persistent domain model that DOES flow to a database/sql sink.
// CardNumber and CVV are both panscanner-recognized sensitive keywords.
type Card struct {
	CardNumber string
	CVV        string
}

// Save wires Card.CardNumber and Card.CVV into a database/sql DB.Exec call.
func Save(db *sql.DB, c Card) error {
	_, err := db.Exec(
		"INSERT INTO cards (number, cvv) VALUES (?, ?)",
		c.CardNumber,
		c.CVV,
	)
	return err
}
