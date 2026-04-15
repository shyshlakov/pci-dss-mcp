// Package models is a synthetic fixture for sqlscanner tests.
// Card struct with encryption hooks: Number is encrypted, ExpMonth/ExpYear
// should NOT be flagged because panProtected=true (D-17b).
package models

const CardTableName = "cards"

type Card struct {
	ID       string `gorm:"column:id;primaryKey"`
	Number   string `gorm:"column:number"`
	ExpMonth int64  `gorm:"column:exp_month"`
	ExpYear  int64  `gorm:"column:exp_year"`
	Last4    string `gorm:"column:last4"`
	Mask     string `gorm:"column:mask"`
	Hash     string `gorm:"column:hash"`
}

func (c *Card) TableName() string { return CardTableName }

func Encrypt(s string) (string, error) { return s, nil }
func Decrypt(s string) (string, error) { return s, nil }

func (c *Card) BeforeCreate(tx interface{}) error {
	c.Number, _ = Encrypt(c.Number)
	return nil
}

func (c *Card) AfterFind(tx interface{}) error {
	c.Number, _ = Decrypt(c.Number)
	return nil
}
