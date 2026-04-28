package http_input

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type panValidationRequest struct {
	Card string `json:"card" validate:"required,len=16"`
	CVV  string `json:"cvv" validate:"required,len=3"`
}

func ValidatorPanValueLog(c *gin.Context) {
	var r panValidationRequest
	if err := c.ShouldBindJSON(&r); err != nil {
		c.AbortWithStatus(400)
		return
	}
	v := validator.New()
	if err := v.Struct(&r); err != nil {
		for _, fe := range err.(validator.ValidationErrors) {
			slog.Error("validation failed", "field", fe.Field(), "value", fe.Value())
		}
	}
}
