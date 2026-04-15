package model

type Card struct {
	ID     uint   `gorm:"primaryKey"`
	Number string `gorm:"column:number"`
	Last4  string `gorm:"column:last4"`
}

func (c *Card) BeforeCreate(tx interface{}) error {
	c.Number = Encrypt(c.Number)
	return nil
}

func Encrypt(s string) string { return s }

func (Card) TableName() string { return "cards" }
