package http_input

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

func AccessLog(c *gin.Context) {
	start := time.Now()
	c.Next()

	slog.InfoContext(c.Request.Context(), "request",
		slog.Group("httpRequest",
			"requestMethod", c.Request.Method,
			"requestUrl", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"remoteIp", c.Request.RemoteAddr,
			"userAgent", c.GetHeader("user-agent"),
			"referer", c.GetHeader("referer"),
			"latency", time.Since(start).String(),
		),
	)
}
