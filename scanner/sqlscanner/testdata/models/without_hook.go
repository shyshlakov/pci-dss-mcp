// Package models is a synthetic fixture for sqlscanner tests. This file
// contains a gorm-style struct that has sensitive cardholder column tags but
// NO BeforeCreate / BeforeSave / AfterFind method referencing Encrypt/Decrypt.
// The scanner must emit both GORM-SENSITIVE-TAG (HIGH) and
// GORM-NO-ENCRYPT-HOOK (HIGH) for this struct.
package models

// Account stores a sensitive PAN with no encryption hook wired.
type Account struct {
	ID  uint
	PAN string `db:"pan"`
}

// Harmless method — does NOT contain Encrypt/Decrypt.
func (a *Account) TableName() string { return "accounts" }
