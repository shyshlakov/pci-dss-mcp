package cache

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/redis"
)

func StoreCard(ctx context.Context, rdb *redis.Client, id, cardData string) error {
	return rdb.Set(ctx, "card:"+id, cardData, 0).Err()
}
