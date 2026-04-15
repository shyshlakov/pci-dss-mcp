package testzap

import (
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ZapMiddleware demonstrates zap field extraction patterns:
// - zap.String("key", val)
// - zap.Int("key", val)
// - zap.Error(err) — implicit field name "error"
// - zap.Duration("key", val)
func ZapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger, _ := zap.NewProduction()
		uid := r.Header.Get("X-User-ID")
		code := http.StatusOK
		dur := time.Second
		var err error

		logger.Info("request",
			zap.String("user_id", uid),
			zap.Int("status_code", code),
			zap.Error(err),
			zap.Duration("latency", dur),
		)

		next.ServeHTTP(w, r)
	})
}
