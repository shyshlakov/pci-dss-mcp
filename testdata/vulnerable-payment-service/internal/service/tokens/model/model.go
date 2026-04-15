package model

type Card struct {
	Number string
	CVV    string
	Holder string
	Expiry string
}

type TokenRequest struct {
	Card Card
}
