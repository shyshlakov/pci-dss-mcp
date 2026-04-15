//go:build ignore

package testcrossfile

import "github.com/gin-gonic/gin"

// TokensHandler handles token operations — payment-related CRUD.
type TokensHandler struct{}

// InstallRoutes registers token routes on the given router group.
// The handler itself has ZERO logging — it relies entirely on middleware
// set up in a sibling file (crossfile_middleware.go).
func (h *TokensHandler) InstallRoutes(group *gin.RouterGroup) {
	sub := group.Group("/tokens/v1")
	sub.POST("/create", h.CreateToken)
	sub.DELETE("/:id", h.DeleteToken)
}

// CreateToken handles token creation. No logging here — covered by middleware.
func (h *TokensHandler) CreateToken(c *gin.Context) {
	c.JSON(200, gin.H{"status": "created"})
}

// DeleteToken handles token deletion. No logging here — covered by middleware.
func (h *TokensHandler) DeleteToken(c *gin.Context) {
	c.JSON(200, gin.H{"status": "deleted"})
}
