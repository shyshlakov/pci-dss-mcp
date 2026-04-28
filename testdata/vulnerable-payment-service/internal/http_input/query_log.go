package http_input

import (
	"log/slog"
	"net/http"
)

func LogQueryToken(w http.ResponseWriter, r *http.Request) {
	slog.Info("verify",
		slog.String("token", r.URL.Query().Get("token")),
	)
	w.WriteHeader(http.StatusOK)
}
