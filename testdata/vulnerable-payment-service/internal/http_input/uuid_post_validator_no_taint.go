package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func UuidPostValidatorNoTaint(c *gin.Context) {
	id, err := uuid.Parse(c.Param("widget_id"))
	if err != nil {
		c.AbortWithStatus(400)
		return
	}
	slog.Info("widget loaded", "widget_id", id.String())
}
