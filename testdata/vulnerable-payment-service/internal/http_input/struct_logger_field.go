package http_input

import (
	"io"
	"log/slog"
	"net/http"
)

type DecodeHandler struct {
	log *slog.Logger
}

func NewDecodeHandler(l *slog.Logger) *DecodeHandler {
	return &DecodeHandler{log: l}
}

func (h *DecodeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error("read body failed", "err", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.log.Error("decode failed", "body", string(raw))
	w.WriteHeader(http.StatusOK)
}
