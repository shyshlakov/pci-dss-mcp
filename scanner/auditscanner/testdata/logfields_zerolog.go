package testzerolog

import (
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// ZerologMiddleware demonstrates zerolog field extraction patterns:
// - .Str("key", val) chain call
// - .Int("key", val) chain call
// - .Err(err) — implicit field name "error"
// - .Dur("key", val) chain call
func ZerologMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		code := http.StatusOK
		var err error
		dur := time.Second

		log.Info().
			Str("request_id", id).
			Int("status", code).
			Err(err).
			Dur("elapsed", dur).
			Msg("request")

		next.ServeHTTP(w, r)
	})
}
