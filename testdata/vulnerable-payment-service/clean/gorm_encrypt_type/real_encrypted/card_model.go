package real_encrypted

type CardToken struct {
	ID     uint         `gorm:"primaryKey"`
	Number SecureString `gorm:"column:number"`
	Last4  string       `gorm:"column:last4"`
}

func (CardToken) TableName() string { return "card_tokens" }
