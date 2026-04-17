package admin

import (
	"encoding/json"
	"net/http"
)

func InstallAdminPanelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/payments/events", HandleAdminUserEventsCallback)
}

func HandleAdminUserEventsCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "rotated-token",
		HttpOnly: true,
		Secure:   true,
	})
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}
