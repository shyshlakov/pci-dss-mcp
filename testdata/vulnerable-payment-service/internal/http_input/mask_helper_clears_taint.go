package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func LogPathParamMasked(c *gin.Context) {
	raw := c.Param("bin")
	slog.Info("lookup",
		slog.String("bin", Maskify(raw)),
	)
}
