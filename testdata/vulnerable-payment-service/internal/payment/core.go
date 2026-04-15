package payment

import (
	"fmt"
	"net/http"
)

// fixture: abstract "Execute" name + /payment/ path + *Card
// param exercise signals 2 + 4. ERR-LEAK-FORMAT must fire HIGH on the
// fmt.Fprintf line below once migrates errorscanner.

type Card struct {
	Number string
	CVV    string
}

type Service struct{}

func (s *Service) Execute(w http.ResponseWriter, r *http.Request, card *Card) {
	err := s.doWork(card)
	fmt.Fprintf(w, "payment failed: %v", err)
}

func (s *Service) doWork(card *Card) error {
	return fmt.Errorf("placeholder: %s", card.Number)
}
