package loggerconst

// Log field name constants — simulates the pattern from reference payment service
// internal/logger/constant.go where all field names are constants.
const (
	LogKeyRequestID  = "request_id"
	LogKeyIP         = "ip"
	LogKeyURL        = "url"
	LogKeyHTTPMethod = "http.method"
	LogKeyHTTPStatus = "http.status"
)
