package cache

import (
	"context"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/redis"
)

func StoreNoExpire(ctx context.Context, rdb *redis.Client, key, value string) error {
	return rdb.Set(ctx, "card:"+key, value, redis.KeepTTL).Err()
}
