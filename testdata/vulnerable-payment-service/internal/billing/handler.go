package billing

import (
	"fmt"
	"net/http"
)

// fixture: abstract "HandleRequest" name + /billing/ path +
// PAN field access exercise signals 2 + 5. ERR-LEAK-FORMAT must fire HIGH
// on the fmt.Fprintf line below once migrates errorscanner.

type Invoice struct {
	PAN string `json:"pan"`
}

func HandleRequest(w http.ResponseWriter, r *http.Request, inv *Invoice) {
	err := validate(inv)
	fmt.Fprintf(w, "billing failed: %v", err)
}

func validate(inv *Invoice) error {
	return fmt.Errorf("invalid PAN: %s", inv.PAN)
}
