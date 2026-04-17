package webhook

import (
	"encoding/json"
	"net/http"
)

func InstallStripeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/stripe", HandleStripeWebhook)
}

func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var event map[string]any
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	switch event["type"] {
	case "invoice.payment_succeeded":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}
}
