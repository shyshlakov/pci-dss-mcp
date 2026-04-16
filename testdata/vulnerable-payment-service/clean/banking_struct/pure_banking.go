package banking_struct

type BankAccount struct {
	ID            string
	AccountNumber []byte
	IBAN          string
	BIC           string
	RoutingNumber string
	AccountHolder string
}
