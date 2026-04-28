package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func ApikeyUuidBranchLog(c *gin.Context) {
	rawApiKey := c.Param("apiKey")
	parsedID, err := uuid.Parse(rawApiKey)
	if err != nil {
		slog.Error("invalid api_key", "value", rawApiKey)
		c.AbortWithStatus(400)
		return
	}
	slog.Info("auth", "api_key", parsedID.String())
}
