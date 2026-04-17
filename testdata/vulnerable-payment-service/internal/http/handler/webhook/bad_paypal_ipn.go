package webhook

import (
	"encoding/json"
	"net/http"
)

func InstallPaypalIPNRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/paypal/ipn", ExecutePaypalIPN)
}

func ExecutePaypalIPN(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var ipn map[string]any
	if err := json.NewDecoder(r.Body).Decode(&ipn); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
