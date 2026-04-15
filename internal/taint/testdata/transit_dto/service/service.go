package service

import (
	"net/http"
	"strings"

	"example.com/transitdto/requests"
)

// Tokenize forwards the request DTO's CVV straight to an HTTP POST —
// exercising R3 (param binding) + R5 (HTTPClient sink hit) and
// demonstrating that no database/sql sink is reachable (so FlowsTo for
// SinkDBStore returns false).
func Tokenize(req requests.TokenizeRequest) error {
	client := &http.Client{}
	resp, err := client.Post(
		"https://visa.example/vts",
		"application/json",
		strings.NewReader(req.CVV),
	)
	if err != nil {
		return err
	}
	if resp != nil && resp.Body != nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			return closeErr
		}
	}
	return nil
}
