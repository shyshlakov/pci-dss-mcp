package http_input

import (
	"bytes"
	"io"
	"log/slog"

	"github.com/gin-gonic/gin"
)

func BytesBufferBodyLog(c *gin.Context) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, c.Request.Body); err != nil {
		slog.Error("decode failed", "err", err.Error())
		return
	}
	slog.Error("decode failed", "body", buf.String())
}
