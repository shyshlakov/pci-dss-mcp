package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func LogRouteTemplate(c *gin.Context) {
	slog.Info("matched route",
		slog.String("route", c.FullPath()),
	)
}
