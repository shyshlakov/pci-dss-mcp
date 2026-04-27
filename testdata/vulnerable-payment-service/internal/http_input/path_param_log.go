package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func LogPathParam(c *gin.Context) {
	slog.Info("lookup",
		slog.String("bin", c.Param("bin")),
	)
}
