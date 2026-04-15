package model

type LeakedToken struct {
	ID         uint   `gorm:"primaryKey"`
	CVV        string `gorm:"column:cvv"`
	PAN        string `gorm:"column:pan"`
	HolderName string `gorm:"column:holder_name"`
}

func (LeakedToken) TableName() string { return "leaked_cards" }
