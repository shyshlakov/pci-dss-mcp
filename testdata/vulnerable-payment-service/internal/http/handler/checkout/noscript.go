package checkout

import (
	"html/template"
	"net/http"
)

func RenderCheckoutNoScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	tmpl := template.Must(template.New("noscript").Parse("<html><body>Pay</body></html>"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
