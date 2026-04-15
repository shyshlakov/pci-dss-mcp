package storedmodel

import "database/sql"

// Repo embeds *sql.DB so that repo.Exec() is a promoted method call. This
// exercises A2 / RESEARCH §Pitfall 6: the sink resolver must walk
// types.NewMethodSet(types.NewPointer(named)) to pick up promoted methods
// on embedded pointer fields.
type Repo struct {
	*sql.DB
}

// SaveEmbedded calls repo.Exec — which, thanks to promotion, resolves to
// the same (*sql.DB).Exec *types.Func as a direct db.Exec. The sink engine
// must match it for R5.
func (r *Repo) SaveEmbedded(rawNumber string) error {
	_, err := r.Exec("INSERT INTO cards (number) VALUES (?)", rawNumber)
	return err
}
