package model

import (
	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/crypto"
)

type FakeSecureToken struct {
	ID     uint                      `gorm:"primaryKey"`
	Number crypto.FakeEncryptedString `gorm:"column:number"`
	Last4  string                    `gorm:"column:last4"`
}

func (FakeSecureToken) TableName() string { return "fake_secure_tokens" }
