package payment

import "net/http"

func Charge(w http.ResponseWriter, r *http.Request) {
	card := []byte("4111111111111111")
	processCharge(card)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
	for i := range card {
		card[i] = 0
	}
}

func processCharge(_ []byte) {}
