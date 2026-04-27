package http_input

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func EchoParamToWriter(c *gin.Context) {
	id := c.Param("id")
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.Write([]byte(id))
}
