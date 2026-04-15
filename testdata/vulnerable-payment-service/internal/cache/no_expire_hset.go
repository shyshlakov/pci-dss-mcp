package cache

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/redis"
)

func CachePaymentCard(ctx context.Context, rdb *redis.Client, cardNumber string) error {
	return rdb.HSet(ctx, "pan_cache", "card", cardNumber).Err()
}
