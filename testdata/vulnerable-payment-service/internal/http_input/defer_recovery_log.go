package http_input

import (
	"log/slog"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

func RecoverAndLog(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered",
				"value", r,
				"trace", string(debug.Stack()),
			)
		}
	}()
	if c.Param("crash") == "yes" {
		panic(c.Param("crash"))
	}
}
