package util

import "net/http"

func ProcessCardBuffer(w http.ResponseWriter, r *http.Request) {
	card := []byte("4111111111111111")
	defer clearCard(card)
	if len(card) == 0 {
		http.Error(w, "empty", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func clearCard(card []byte) {
	for i := range card {
		card[i] = 0
	}
}
