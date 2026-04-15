package checkout

import (
	"html/template"
	"net/http"
)

func RenderCheckout(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.New("checkout").Parse("<html><body>Pay</body></html>"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
