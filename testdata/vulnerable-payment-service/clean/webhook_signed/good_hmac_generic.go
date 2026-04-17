package webhooksigned

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
)

func InstallHMACGenericRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/hooks/inbound", HandleHMACGenericCallback)
}

func HandleHMACGenericCallback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte("inbound-secret"))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	got := r.Header.Get("X-Signature")
	if !hmac.Equal([]byte(expected), []byte(got)) {
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
