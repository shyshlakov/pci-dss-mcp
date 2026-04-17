package webhooksigned

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
)

func InstallLocalHelperRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/stripe-helper", HandleLocalHelperWebhook)
}

func HandleLocalHelperWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	if !verifyStripeSignature(r, body) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func verifyStripeSignature(r *http.Request, body []byte) bool {
	mac := hmac.New(sha256.New, []byte("local-secret"))
	mac.Write(body)
	expected := mac.Sum(nil)
	got := []byte(r.Header.Get("Stripe-Signature"))
	return hmac.Equal(expected, got)
}
