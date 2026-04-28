package http_input

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

func ZerologCtxErr(c *gin.Context) {
	parseErr := fmt.Errorf("uuid: invalid input %q", c.Param("id"))
	err := fmt.Errorf("decode id: %w", parseErr)
	log.Ctx(c.Request.Context()).
		Error().
		Err(err).
		Send()
}
