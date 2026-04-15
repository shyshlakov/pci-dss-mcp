// Package models is a synthetic fixture for sqlscanner tests.
// BadCard struct WITHOUT encryption hooks: Number should be HIGH,
// ExpMonth/ExpYear should be MEDIUM (panProtected=false, D-17c).
package models

type BadCard struct {
	ID       string `gorm:"column:id;primaryKey"`
	Number   string `gorm:"column:number"`
	ExpMonth int64  `gorm:"column:exp_month"`
	ExpYear  int64  `gorm:"column:exp_year"`
}

func (c *BadCard) TableName() string { return "cards" }
