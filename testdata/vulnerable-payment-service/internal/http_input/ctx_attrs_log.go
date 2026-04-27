package http_input

import (
	"context"
	"log/slog"

	"github.com/gin-gonic/gin"
)

type ctxKey int

const loggerKey ctxKey = iota

func InstallContextLogger(c *gin.Context) {
	bound := slog.With(
		"path", c.Request.URL.Path,
		"user_agent", c.GetHeader("user-agent"),
	)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), loggerKey, bound))
	c.Next()
}

func CtxLog(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

func DownstreamHandler(c *gin.Context) {
	CtxLog(c.Request.Context()).Info("operation completed")
}
