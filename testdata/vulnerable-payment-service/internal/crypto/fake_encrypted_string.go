package crypto

import (
	"database/sql/driver"
	"encoding/base64"
	"errors"
)

type FakeEncryptedString string

func (fes FakeEncryptedString) Value() (driver.Value, error) {
	return base64.StdEncoding.EncodeToString([]byte(fes)), nil
}

func (fes *FakeEncryptedString) Scan(value interface{}) error {
	if value == nil {
		*fes = ""
		return nil
	}
	str, ok := value.(string)
	if !ok {
		return errors.New("FakeEncryptedString.Scan: expected string")
	}
	raw, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return err
	}
	*fes = FakeEncryptedString(raw)
	return nil
}
