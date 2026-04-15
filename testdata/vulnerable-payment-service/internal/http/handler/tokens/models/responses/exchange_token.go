package responses

type ExchangeTokenResponse struct {
	Token     string `json:"token"`
	MaskedPAN string `json:"masked_pan"`
	CVV       string `json:"cvv"`
	ExpiresAt int64  `json:"expires_at"`
}
