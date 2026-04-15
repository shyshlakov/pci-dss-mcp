package auth

import "net/http"

func AuthorizeCharge(w http.ResponseWriter, r *http.Request) {
	card := []byte("4111111111111111")
	for i := range card {
		card[i] = 0
	}
	authorizeCard(card)
	w.WriteHeader(http.StatusOK)
}

func authorizeCard(_ []byte) {}
