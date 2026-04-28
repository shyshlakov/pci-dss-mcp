package http_input

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func WrapChainHandler(c *gin.Context) {
	if err := decodePayload(c.Param("payload")); err != nil {
		wrapped := fmt.Errorf("decode payload: %w", err)
		final := fmt.Errorf("handler step: %w", wrapped)
		slog.Error("op failed", "err", final.Error())
	}
}

func decodePayload(s string) error {
	if s == "" {
		return errors.New("empty payload")
	}
	return fmt.Errorf("invalid payload value=%s", s)
}
