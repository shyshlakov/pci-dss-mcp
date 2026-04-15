//go:build ignore

package testcrossfile

import (
	"github.com/company/middleware"
	"github.com/gin-gonic/gin"
)

// SetupExternal configures routes using an external middleware package.
// The import path "github.com/company/middleware" contains the word "middleware",
// which triggers the D-06 heuristic trust.
func SetupExternal(r *gin.Engine) {
	apiGroup := r.Group("/api/v2")
	middleware.Install(apiGroup)

	apiGroup.POST("/pay", ExternalPayHandler)
}

// ExternalPayHandler relies on external middleware for logging.
func ExternalPayHandler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
