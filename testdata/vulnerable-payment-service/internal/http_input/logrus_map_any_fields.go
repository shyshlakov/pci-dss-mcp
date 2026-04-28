package http_input

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func LogrusMapAnyFields(c *gin.Context) {
	logrus.WithFields(map[string]any{
		"path":    c.Request.URL.Path,
		"user_id": c.Query("user_id"),
		"ua":      c.GetHeader("User-Agent"),
	}).Info("request received")
}
