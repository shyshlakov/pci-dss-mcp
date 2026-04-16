package real_encrypted

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"io"
)

var encryptionKey = []byte("0123456789abcdef0123456789abcdef")

type SecureString string

func (s SecureString) Value() (driver.Value, error) {
	plaintext := []byte(s)

	block, err := aes.NewCipher(encryptionKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *SecureString) Scan(value interface{}) error {
	if value == nil {
		*s = ""
		return nil
	}
	str, ok := value.(string)
	if !ok {
		return errors.New("SecureString.Scan: not a string")
	}
	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return errors.New("SecureString.Scan: ciphertext too short")
	}
	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	*s = SecureString(plaintext)
	return nil
}
