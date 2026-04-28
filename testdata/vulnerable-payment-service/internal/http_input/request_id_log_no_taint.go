package http_input

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
)

func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b)
}

func RequestIdLogNoTaint() {
	reqID := generateRequestID()
	slog.Info("processed", "request_id", reqID)
}
