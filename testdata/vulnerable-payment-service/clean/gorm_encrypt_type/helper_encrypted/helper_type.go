package helper_encrypted

import (
	"database/sql/driver"
	"errors"
)

type HelperEncryptedString string

func (hes HelperEncryptedString) Value() (driver.Value, error) {
	return EncryptPAN(string(hes))
}

func (hes *HelperEncryptedString) Scan(value interface{}) error {
	if value == nil {
		*hes = ""
		return nil
	}
	b, ok := value.([]byte)
	if !ok {
		return errors.New("HelperEncryptedString.Scan: expected []byte")
	}
	*hes = HelperEncryptedString(b)
	return nil
}
