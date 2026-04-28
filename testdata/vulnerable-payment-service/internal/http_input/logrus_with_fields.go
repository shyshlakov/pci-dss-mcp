package http_input

import (
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func LogrusFieldsHandler(c *gin.Context) {
	logrus.WithFields(logrus.Fields{
		"req_id":   c.GetHeader("X-Request-ID"),
		"user_id":  c.Query("user_id"),
		"endpoint": c.Request.URL.Path,
	}).Info("request received")
}
