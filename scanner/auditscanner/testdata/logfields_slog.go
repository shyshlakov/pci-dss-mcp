package testslog

import (
	"log/slog"
	"net/http"
)

// LogMiddleware demonstrates slog field extraction patterns:
// - slog.String("key", val) function call
// - slog.Int("key", val) function call
// - slog.Any("key", val) function call
// - slog.Attr{Key: "key", Value: slog.StringValue("val")} struct literal
func LogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := r.Header.Get("X-User-ID")
		code := http.StatusOK
		meta := map[string]string{"source": "api"}

		// Pattern 1: slog field function calls
		slog.Info("request",
			slog.String("user_id", uid),
			slog.Int("status", code),
			slog.Any("metadata", meta),
		)

		// Pattern 2: slog.Attr struct literal
		attrs := []slog.Attr{
			{Key: "event", Value: slog.StringValue("request")},
		}
		_ = attrs

		next.ServeHTTP(w, r)
	})
}
