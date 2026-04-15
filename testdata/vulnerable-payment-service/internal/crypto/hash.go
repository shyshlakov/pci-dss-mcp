package crypto

import "crypto/md5"

func HashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}
