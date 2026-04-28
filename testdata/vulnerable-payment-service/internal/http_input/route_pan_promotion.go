package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func LookupByPAN(c *gin.Context) {
	pan := c.Param("pan")
	slog.Info("lookup",
		slog.String("pan", pan),
	)
}
