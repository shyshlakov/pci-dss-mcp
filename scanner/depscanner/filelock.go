package depscanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofrs/flock"
)

var errLockBusy = errors.New("cache lock held by another process")

func withCacheLock(ctx context.Context, cachePath string, fn func() error) error {
	lock := flock.New(cachePath + ".lock")
	lockCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("acquire cache lock: %w", err)
	}
	if !locked {
		return errLockBusy
	}
	defer func() {
		if uerr := lock.Unlock(); uerr != nil {
			slog.Warn("unlock cache file", "err", uerr)
		}
	}()
	return fn()
}
