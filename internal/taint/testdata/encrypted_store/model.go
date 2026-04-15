package encryptedstore

import "database/sql"

// Card carries a sensitive CVV that is piped through an intermediate
// Encrypt() helper before reaching database/sql.DB.Exec — exercising R3
// (param binding into Encrypt), R4 (return-tainted propagation from
// Encrypt back to Save's local variable), and R5 (sink hit).
type Card struct {
	CVV string
}

// Encrypt is a no-op in the fixture but modelling a real crypto helper: its
// return value inherits the taint of its argument because flags flow via
// the R4 "callee returns tainted" path.
func Encrypt(s string) string {
	return s
}

// Save exercises the cross-function propagation chain.
func Save(db *sql.DB, c Card) error {
	enc := Encrypt(c.CVV)
	_, err := db.Exec("INSERT INTO cards (cvv) VALUES (?)", enc)
	return err
}
