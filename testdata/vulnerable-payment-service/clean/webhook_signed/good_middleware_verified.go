package webhooksigned

import (
	"encoding/json"
	"net/http"
)

func InstallMiddlewareVerifiedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/inbound", VerifyWebhookSignatureMiddleware(HandleMiddlewareVerifiedCallback))
}

func VerifyWebhookSignatureMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Webhook-Signature") == "" {
			http.Error(w, "missing signature", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func HandleMiddlewareVerifiedCallback(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
