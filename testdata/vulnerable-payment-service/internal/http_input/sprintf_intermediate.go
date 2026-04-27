package http_input

import (
	"fmt"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func SprintfIntermediate(c *gin.Context) {
	slog.Info("incoming",
		slog.String("input", fmt.Sprintf("v=%s", c.Param("v"))),
	)
}
