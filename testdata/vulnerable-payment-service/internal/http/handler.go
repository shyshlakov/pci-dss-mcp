package http

import (
	"github.com/gin-gonic/gin"

	tokens "github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/http/handler/tokens"
)

func RegisterRoutes(r *gin.Engine) {
	r.POST("/tokenize", gin.WrapF(tokens.Tokenize))
}
