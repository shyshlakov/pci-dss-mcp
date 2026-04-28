package http_input

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type Token struct {
	raw string
}

func (t Token) String() string { return t.raw }

func StringerTokenErrorf(c *gin.Context) {
	t := Token{raw: c.GetHeader("Authorization")}
	_ = c.AbortWithError(401, fmt.Errorf("token invalid: %v", t))
}
