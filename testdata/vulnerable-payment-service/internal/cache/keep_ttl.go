package cache

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/redis"
)

func StoreCVV(ctx context.Context, rdb *redis.Client, id, cvv string) error {
	return rdb.Set(ctx, "cvv:"+id, cvv, redis.KeepTTL).Err()
}
