package tokens

import "database/sql"

func StoreCVV(db *sql.DB, cvv string) error {
	_, err := db.Exec("INSERT INTO sensitive_data (cvv) VALUES (?)", cvv)
	return err
}
