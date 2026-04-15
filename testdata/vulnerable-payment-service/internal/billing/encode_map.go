package billing

import (
	"encoding/json"
	"net/http"
)

// fixture: abstract Submit name + /billing/ path +
// CHD parameter type exercise signals 2 + 4. ERR-LEAK-ENCODE must fire
// CRITICAL on the json.NewEncoder(...).Encode(map[string]any{...}) line
// once the containsErrReference walker enters CompositeLit elements (B-05).

type Card struct {
	Number string
}

type EncodeHandler struct{}

func (h *EncodeHandler) Submit(w http.ResponseWriter, r *http.Request, card *Card) {
	if err := h.process(card); err != nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "code": 500})
		return
	}
}

func (h *EncodeHandler) process(card *Card) error { return nil }
