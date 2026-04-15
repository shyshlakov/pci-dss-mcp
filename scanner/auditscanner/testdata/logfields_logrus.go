package testlogrus

import (
	"context"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// LogKeyHTTPStatus is a local constant for map-index-assign pattern.
const LogKeyHTTPStatus = "http.status"

// EnrichLogger demonstrates multiple logrus field extraction patterns:
// - Composite literal: logrus.Fields{"key": val}
// - WithField: entry.WithField("key", val)
// - Map-index-assign with string literal: fields["key"] = val
// - Map-index-assign with local constant: fields[LogKeyHTTPStatus] = val
// - Local helper call: withExtraFields(fields)
func EnrichLogger(ctx context.Context, r *http.Request) {
	startTime := time.Now()
	requestID := ctx.Value("request_id").(string)
	path := r.URL.Path
	clientIP := r.RemoteAddr
	status := http.StatusOK
	dur := time.Since(startTime)

	// Pattern 1: logrus.Fields composite literal
	entry := logrus.WithFields(logrus.Fields{
		"request_id": requestID,
		"url":        path,
	})

	// Pattern 2: WithField single-field call
	entry = entry.WithField("ip", clientIP)

	// Pattern 3: Map-index-assign with string literal key
	fields := make(logrus.Fields)
	fields["elapsed"] = dur.String()

	// Pattern 4: Map-index-assign with local constant key
	fields[LogKeyHTTPStatus] = status

	// Pattern 5: Local helper call (1-level following)
	withExtraFields(fields)

	entry.WithFields(fields).Info("request completed")
}

// withExtraFields adds version information to the fields map.
func withExtraFields(fields logrus.Fields) {
	ver := "1.0.0"
	fields["version"] = ver
}
