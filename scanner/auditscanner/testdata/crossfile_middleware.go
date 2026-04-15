//go:build ignore

package testcrossfile

import (
	"github.com/gin-gonic/gin"
)

// requestLogger is a middleware that adds structured logging context.
func requestLogger(c *gin.Context) {
	c.Next()
}

// SetupRoutes configures the API routes with middleware and handler registration.
// Common Gin pattern: middleware.Install(apiV1Group) followed by
// handler.InstallRoutes(apiV1Group).
func SetupRoutes(r *gin.Engine) {
	apiV1Group := r.Group("/api/v1")

	// Apply logging middleware to the group.
	apiV1Group.Use(requestLogger)

	// Register token handler routes on the middleware-covered group.
	tokensHV1 := &TokensHandler{}
	tokensHV1.InstallRoutes(apiV1Group)
}
