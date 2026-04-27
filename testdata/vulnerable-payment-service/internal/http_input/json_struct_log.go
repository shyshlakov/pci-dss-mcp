package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

type chargeRequest struct {
	CardNumber string `json:"card_number"`
	CVV        string `json:"cvv"`
	Amount     int64  `json:"amount"`
}

func LogJSONStruct(c *gin.Context) {
	var req chargeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return
	}
	slog.Info("charge request decoded", slog.Any("req", req))
}
