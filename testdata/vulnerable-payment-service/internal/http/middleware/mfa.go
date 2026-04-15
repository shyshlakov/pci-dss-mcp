package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func RequireMFA() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-MFA-Verified") != "true" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
