package tokens

import (
	"log/slog"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/service/tokens/model"
)

func LogProcessed(card model.Card) {
	cardNumber := card.Number
	slog.Info("card processed", "value", cardNumber)
}
