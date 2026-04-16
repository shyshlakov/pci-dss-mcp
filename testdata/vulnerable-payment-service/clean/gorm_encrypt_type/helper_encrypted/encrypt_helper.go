package helper_encrypted

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"os"
)

func loadKey() []byte {
	return []byte(os.Getenv("HELPER_ENCRYPT_KEY"))
}

func EncryptPAN(plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(loadKey())
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}
