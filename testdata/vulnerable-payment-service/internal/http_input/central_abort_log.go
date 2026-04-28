package http_input

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetMerchant(c *gin.Context) {
	merchantID, err := parseMerchantID(c.Param("merchant_id"))
	if err != nil {
		Abort(c, fmt.Errorf("parse merchant id from path: %w", err))
		return
	}
	_ = merchantID
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func parseMerchantID(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty merchant id")
	}
	return s, nil
}

func Abort(c *gin.Context, err error) {
	slog.ErrorContext(c.Request.Context(), "request error",
		"error", err.Error(),
	)
	c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}
