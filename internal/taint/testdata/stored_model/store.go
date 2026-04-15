package storedmodel

import "database/sql"

// Save wires Card.Number and Card.CVV into a database/sql DB.Exec call —
// this is the canonical "stored CHD" flow the taint engine must detect via
// R3 (param binding) + R5 (sink hit) against the SinkDBStore library.
func Save(db *sql.DB, c Card) error {
	_, err := db.Exec(
		"INSERT INTO cards (number, cvv) VALUES (?, ?)",
		c.Number,
		c.CVV,
	)
	return err
}
