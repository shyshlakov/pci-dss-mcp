package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

var debugMode = false

func ConditionalDebugLog(c *gin.Context) {
	var req chargeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return
	}
	if debugMode {
		slog.Info("debug request", slog.Any("req", req))
	}
}
