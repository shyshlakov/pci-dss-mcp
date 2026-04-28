package http_input

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func ConfirmCharge(c *gin.Context) {
	id, err := parseChargeID(c.Param("charge_id"))
	if err != nil {
		AbortWithErrorLog(c, fmt.Errorf("parse charge id from path: %w", err))
		return
	}
	_ = id
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func parseChargeID(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty id")
	}
	return s, nil
}

func AbortWithErrorLog(c *gin.Context, err error) {
	slog.ErrorContext(c.Request.Context(), "request error",
		"error", err.Error(),
	)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}
