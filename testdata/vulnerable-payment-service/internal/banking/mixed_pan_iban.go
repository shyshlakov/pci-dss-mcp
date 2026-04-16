package banking

type HybridPaymentAccount struct {
	AccountNumber string
	IBAN          string
	CVV           string
	ExpiryMonth   int
	CardNumber    string
}
