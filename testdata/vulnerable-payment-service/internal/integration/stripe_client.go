package integration

type StripeChargeRequest struct {
	Amount     int64  `json:"amount"`
	CardNumber string `json:"card_number"`
	Currency   string `json:"currency"`
}

func NewStripeChargeRequest(amount int64, card, currency string) StripeChargeRequest {
	return StripeChargeRequest{Amount: amount, CardNumber: card, Currency: currency}
}
