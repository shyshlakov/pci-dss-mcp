package main

import (
	"example.com/transitdto/requests"
	"example.com/transitdto/service"
)

func main() {
	req := requests.TokenizeRequest{CVV: "123", PAN: "4111111111111111"}
	if err := service.Tokenize(req); err != nil {
		_ = err
	}
}
