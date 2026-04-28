package http_input

import (
	"log/slog"
	"net/http"
)

func LogAuthHeader(w http.ResponseWriter, r *http.Request) {
	slog.Info("auth check",
		slog.String("auth", r.Header.Get("Authorization")),
	)
	w.WriteHeader(http.StatusOK)
}
