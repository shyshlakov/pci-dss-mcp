package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
)

func GinRecoveryCallbackLog() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, recovered any) {
		slog.Error("panic", "value", recovered, "path", c.Request.URL.Path)
	})
}

func TriggerPanic(c *gin.Context) {
	panic(c.PostForm("card_number"))
}
