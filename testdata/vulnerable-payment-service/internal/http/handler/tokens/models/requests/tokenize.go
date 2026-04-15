package requests

type TokenizeRequest struct {
	CardNumber     string `json:"card_number"`
	CVV            string `json:"cvv"`
	ExpirationDate string `json:"expiration_date"`
	HolderName     string `json:"holder_name"`
}
