// Package models is a synthetic fixture for sqlscanner tests. It contains a
// gorm-style struct that DOES wire application-level encryption via a
// BeforeCreate hook that references an Encrypt helper. The scanner should
// downgrade GORM-SENSITIVE-TAG to INFO for this struct and NOT emit
// GORM-NO-ENCRYPT-HOOK.
package models

// Card is a sensitive cardholder record with a BeforeCreate hook.
type Card struct {
	ID         uint
	CardNumber string `gorm:"column:card_number"`
	CVV        string `gorm:"column:cvv"`
}

// Encrypt is a stub encryption helper (real implementation lives in the host
// project). The scanner only checks the identifier name, not the body.
func Encrypt(s string) string { return s }

// BeforeCreate wires application-level encryption via a gorm lifecycle hook.
// The scanner must detect the Encrypt identifier in this method body.
func (c *Card) BeforeCreate(tx interface{}) error {
	c.CardNumber = Encrypt(c.CardNumber)
	c.CVV = Encrypt(c.CVV)
	return nil
}
