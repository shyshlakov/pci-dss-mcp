package s2shandler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

func InstallStripeWebhookRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/payment/stripe/webhook", ProcessStripeEventWebhook)
}

func ProcessStripeEventWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte("secret-loaded-from-env"))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	got := r.Header.Get("Stripe-Signature")
	if !hmac.Equal([]byte(expected), []byte(got)) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var event map[string]any
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
