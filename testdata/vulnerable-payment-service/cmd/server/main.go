package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/http/middleware"
)

var _ jose.JSONWebEncryption

func main() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	router := gin.New()
	router.Use(middleware.RequestLogger(logger))
	router.Use(middleware.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	if err := router.Run(":8080"); err != nil {
		logger.WithError(err).Fatal("server exited")
	}
}
