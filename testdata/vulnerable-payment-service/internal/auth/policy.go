package auth

import "fmt"

type Policy struct {
	MinPasswordLength int
}

var Default = Policy{MinPasswordLength: 8}

func Validate(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password too short")
	}
	return nil
}
