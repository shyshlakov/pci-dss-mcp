package tokens

import (
	"encoding/json"
	"net/http"
)

func CardMetadata(w http.ResponseWriter, r *http.Request) {
	if err := buildMeta(r); err != nil {
		// pci:fixture intentional ERR-LEAK-ENCODE — do not copy
		json.NewEncoder(w).Encode(err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func buildMeta(_ *http.Request) error { return nil }
