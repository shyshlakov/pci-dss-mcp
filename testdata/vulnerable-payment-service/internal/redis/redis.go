package redis

import (
	"context"
	"time"
)

const KeepTTL time.Duration = -1

type StatusCmd struct{ err error }

func (c *StatusCmd) Err() error { return c.err }

type BoolCmd struct{ err error }

func (c *BoolCmd) Err() error { return c.err }

type Client struct{}

func (c *Client) Set(ctx context.Context, key string, value any, expiration time.Duration) *StatusCmd {
	return &StatusCmd{}
}

func (c *Client) SetNX(ctx context.Context, key string, value any, expiration time.Duration) *BoolCmd {
	return &BoolCmd{}
}

func (c *Client) Expire(ctx context.Context, key string, expiration time.Duration) *BoolCmd {
	return &BoolCmd{}
}

func (c *Client) HSet(ctx context.Context, key string, values ...any) *StatusCmd {
	return &StatusCmd{}
}
