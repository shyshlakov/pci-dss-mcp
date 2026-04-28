package http_input

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v4"
)

func EchoLogPathParam(c echo.Context) error {
	slog.Info("merchant lookup",
		slog.String("merchant", c.Param("merchant")),
	)
	return c.NoContent(http.StatusOK)
}
