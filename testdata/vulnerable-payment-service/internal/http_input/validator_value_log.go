package http_input

import (
	"errors"
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type subscribeRequest struct {
	Email      string `json:"email" binding:"required,email"`
	CardNumber string `json:"card_number" binding:"required"`
}

func ValidateSubscribe(c *gin.Context) {
	var req subscribeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		details := map[string]any{}
		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			for _, fe := range verrs {
				details[fe.Field()] = fe.Value()
			}
		}
		slog.Error("validation failed", slog.Any("details", details))
	}
}
