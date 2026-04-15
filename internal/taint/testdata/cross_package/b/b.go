package b

import (
	"database/sql"

	"example.com/crosspkg/a"
)

// Store wires a.Req.PAN into a database/sql DB.Exec — the taint engine must
// resolve the source in package a and the sink call in package b via
// types.Info.Uses cross-package identity.
func Store(db *sql.DB, r a.Req) error {
	_, err := db.Exec("INSERT INTO t (pan) VALUES (?)", r.PAN)
	return err
}
