// Package storedmodel contains a DB model with gorm tags.
// The struct tag heuristic must classify this as a storage model.
package storedmodel

// CardDB is a gorm-annotated database model. It has both json and gorm tags.
// The struct tag heuristic must classify it as tagClassStorage because the
// presence of gorm tags takes precedence over json tags.
type CardDB struct {
	Number string `gorm:"column:number" json:"number"`
	CVV    string `gorm:"column:cvv" json:"cvv"`
}
