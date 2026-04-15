package http

import (
	"io"
	stdhttp "net/http"
)

const PaymentURL = "http://api.payment.example/charge"

func ChargePlain() ([]byte, error) {
	resp, err := stdhttp.Get(PaymentURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
