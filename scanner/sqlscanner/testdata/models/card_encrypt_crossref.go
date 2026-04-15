// Package models is a synthetic fixture for D-02 cross-reference tests.
// Card struct with gorm tags and BeforeCreate encrypt hook for Number field.
// When cross-referenced with encrypt_crossref.sql:
//   - SQL "number text" finding -> INFO (app-level encryption detected)
//   - SQL "exp_month"/"exp_year" -> suppressed (PAN has Go-level encryption)
package models

const CardTableName = "cards"

type Card struct {
	ID       string `gorm:"column:id;primaryKey"`
	Number   string `gorm:"column:number"`
	ExpMonth int64  `gorm:"column:exp_month"`
	ExpYear  int64  `gorm:"column:exp_year"`
	Last4    string `gorm:"column:last4"`
}

func (c *Card) TableName() string { return CardTableName }

func Encrypt(s string) string { return s }

func (c *Card) BeforeCreate(tx interface{}) error {
	c.Number = Encrypt(c.Number)
	return nil
}
