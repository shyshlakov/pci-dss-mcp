package exchange

import (
	"fmt"
	"net/http"

	_ "github.com/go-jose/go-jose/v4"
)

func Execute(w http.ResponseWriter, r *http.Request) {
	if err := doWork(); err != nil {
		fmt.Fprintf(w, "exchange failed: %v", err)
	}
}

func doWork() error {
	return fmt.Errorf("placeholder")
}
