package http_input

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog/log"
)

func FiberQueryLog(c *fiber.Ctx) error {
	log.Info().
		Str("token", c.Query("token")).
		Msg("token validation")
	return c.SendStatus(fiber.StatusOK)
}
