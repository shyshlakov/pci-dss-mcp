package tokens

import (
	"fmt"
	"net/http"
)

func Detokenize(w http.ResponseWriter, r *http.Request) {
	if err := lookup(r); err != nil {
		fmt.Fprintf(w, "tokenization failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func lookup(_ *http.Request) error { return nil }
