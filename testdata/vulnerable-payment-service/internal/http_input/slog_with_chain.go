package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func ChainedLogger(c *gin.Context) {
	logger := slog.With("path", c.Param("id"))
	logger.Info("step1")
	logger.Info("step2")
	logger.Info("step3")
}
