package crypto_filter_cases

import "errors"

var ErrInvalidToken = errors.New("token has expired and cannot be refreshed")
