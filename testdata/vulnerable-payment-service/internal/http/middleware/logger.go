package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func RequestLogger(logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.WithFields(logrus.Fields{
			LogKeyRequestID: c.GetHeader("X-Request-ID"),
			LogKeyEventType: "http_request",
			LogKeyOutcome:   statusOutcome(c.Writer.Status()),
			"http.status":   c.Writer.Status(),
			"duration_ms":   time.Since(start).Milliseconds(),
		}).Info("request completed")
	}
}

func statusOutcome(status int) string {
	if status >= 200 && status < 400 {
		return "success"
	}
	return "failure"
}
