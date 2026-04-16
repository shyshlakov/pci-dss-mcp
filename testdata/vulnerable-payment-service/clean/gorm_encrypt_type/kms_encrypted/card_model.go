package kms_encrypted

type VaultCard struct {
	ID     uint               `gorm:"primaryKey"`
	Number KMSEncryptedString `gorm:"column:number"`
	Last4  string             `gorm:"column:last4"`
}

func (VaultCard) TableName() string { return "vault_cards" }
