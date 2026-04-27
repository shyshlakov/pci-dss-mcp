package http_input

import (
	"io"
	"log/slog"
	"net/http"
)

func DecodeWithPartialMasking(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		slog.Error("read body failed",
			slog.String("body", string(body)),
			slog.String("err", err.Error()),
		)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	slog.Info("body decoded ok",
		slog.String("body", string(Maskify(string(body)))),
	)
	w.WriteHeader(http.StatusOK)
}
