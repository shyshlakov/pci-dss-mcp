//go:build ignore

package testcrossfile

import "github.com/gin-gonic/gin"

// SetupUncovered configures a route group with NO logging middleware.
func SetupUncovered(r *gin.Engine) {
	adminGroup := r.Group("/admin")
	// No adminGroup.Use(...) with any logger middleware!
	adminGroup.POST("/payment", UncoveredPayment)
}

// UncoveredPayment is a payment handler registered on a group WITHOUT logger middleware.
// This must still fire AUDIT-NO-LOG.
func UncoveredPayment(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
