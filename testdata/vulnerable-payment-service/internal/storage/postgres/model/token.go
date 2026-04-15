package model

import "time"

type Token struct {
	ID        uint   `gorm:"primaryKey"`
	CardID    string `gorm:"column:card_id;index"`
	Number    string `gorm:"column:card_number"`
	CVV       string `gorm:"column:cvv"`
	Holder    string `gorm:"column:holder_name"`
	ExpMonth  int    `gorm:"column:exp_month"`
	ExpYear   int    `gorm:"column:exp_year"`
	CreatedAt time.Time
}

func (Token) TableName() string { return "tokens" }
