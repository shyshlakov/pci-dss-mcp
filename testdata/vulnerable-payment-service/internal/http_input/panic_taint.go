package http_input

import (
	"github.com/gin-gonic/gin"
)

func PanicOnBadID(c *gin.Context) {
	if c.Param("id") == "" {
		panic(c.Param("id"))
	}
}
