package storedmodel

import "database/sql"

// SaveViaLiteral exercises R2 (struct literal field seeding) + A1
// mitigation (types.Info.ObjectOf on composite-literal keys). The
// rawNumber parameter is passed into a Card{Number: rawNumber} literal,
// which tasks propagate.go with tracking taint through the field key
// back to the sql.DB.Exec sink.
func SaveViaLiteral(db *sql.DB, rawNumber string) error {
	c := Card{Number: rawNumber}
	_, err := db.Exec("INSERT INTO cards (number) VALUES (?)", c.Number)
	return err
}
