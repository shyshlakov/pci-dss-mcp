package postgres

import (
	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/storage/postgres/model"
)

type gormDB interface {
	Create(value any) gormDB
	Error() error
}

func PersistCardToken(db gormDB, cardToken *model.Token) error {
	return db.Create(cardToken).Error()
}
