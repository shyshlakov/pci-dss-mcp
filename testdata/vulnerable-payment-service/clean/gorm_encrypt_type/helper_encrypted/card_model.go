package helper_encrypted

type CardData struct {
	ID     uint                  `gorm:"primaryKey"`
	Number HelperEncryptedString `gorm:"column:number"`
	Last4  string                `gorm:"column:last4"`
}

func (CardData) TableName() string { return "card_data" }
