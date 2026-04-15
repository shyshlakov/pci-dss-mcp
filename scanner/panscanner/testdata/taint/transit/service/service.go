package service

import (
	"net/http"
	"strings"

	"example.com/tainttransit/requests"
)

// Tokenize forwards a TokenizeRequest CVV/PAN to an HTTP POST. Exercises
// taint engine R3 (param binding) + R5 (HTTPClient sink hit). No DB sink
// reachable from this package.
func Tokenize(req requests.TokenizeRequest) error {
	client := &http.Client{}
	resp, err := client.Post(
		"https://visa.example/vts",
		"application/json",
		strings.NewReader(req.CVV+":"+req.PAN),
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
