package kms_encrypted

import (
	"context"
	"database/sql/driver"
	"errors"
)

type VaultKMSClient struct{}

func NewVaultKMSClient() *VaultKMSClient { return &VaultKMSClient{} }

func (v *VaultKMSClient) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	_ = ctx
	return plaintext, nil
}

func (v *VaultKMSClient) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	_ = ctx
	return ciphertext, nil
}

var vaultClient = NewVaultKMSClient()

type KMSEncryptedString string

func (kes KMSEncryptedString) Value() (driver.Value, error) {
	return vaultClient.Encrypt(context.Background(), []byte(kes))
}

func (kes *KMSEncryptedString) Scan(value interface{}) error {
	if value == nil {
		*kes = ""
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("KMSEncryptedString.Scan: expected []byte")
	}
	plaintext, err := vaultClient.Decrypt(context.Background(), b)
	if err != nil {
		return err
	}
	*kes = KMSEncryptedString(plaintext)
	return nil
}
