package s2shandler

import (
	"encoding/json"
	"net/http"
)

func InstallGenericConsensusRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/hooks/payment", HandlePaymentNotificationCallback)
}

func HandlePaymentNotificationCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
