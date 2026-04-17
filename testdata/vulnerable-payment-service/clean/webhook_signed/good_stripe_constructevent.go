package webhooksigned

import (
	"encoding/json"
	"io"
	"net/http"
)

type stripeWebhookClient interface {
	ConstructEvent(payload []byte, header string, secret string) (map[string]any, error)
}

var webhook stripeWebhookClient

func InstallVerifiedStripeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/stripe", HandleVerifiedStripeWebhook)
}

func HandleVerifiedStripeWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), "secret-from-env")
	if err != nil {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	_ = event
	w.WriteHeader(http.StatusOK)
}
