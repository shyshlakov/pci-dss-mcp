package card

type MastercardCard struct {
	PrimaryAccountNumber string `json:"primary_account_number"`
	ExpirationDate       string `json:"expiration_date"`
	SecurityCode         string `json:"security_code"`
	HolderName           string `json:"holder_name"`
}
