package webhook

import (
	"encoding/json"
	"net/http"
)

func InstallGenericPaymentHookRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/hooks/payment", ProcessPaymentHookCallback)
}

func ProcessPaymentHookCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	body := make([]byte, r.ContentLength)
	if _, err := r.Body.Read(body); err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
