package payment

import "net/http"

// fixture: abstract Process name + /payment/ path +
// CHD parameter type exercise signals 2 + 4. RET-ZERO-BEFORE-AUTH must
// fire CRITICAL once walkStatements enters IfStmt.Init and classifies the
// zeroCard call ahead of the authorize call (B-06).

type ZeroInitHandler struct{}

func zeroCard(card *Card) bool {
	if card == nil {
		return false
	}
	card.Number = ""
	return true
}

func (h *ZeroInitHandler) Process(w http.ResponseWriter, r *http.Request, card *Card) {
	if zeroed := zeroCard(card); zeroed {
		_ = zeroed
	}
	h.authorize(card)
	w.WriteHeader(http.StatusOK)
}

func (h *ZeroInitHandler) authorize(card *Card) error { return nil }
