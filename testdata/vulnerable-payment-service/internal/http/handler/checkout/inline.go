package checkout

import (
	"html/template"
	"net/http"
)

func RenderCheckoutInline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'")
	tmpl := template.Must(template.New("inline").Parse("<html><body>Pay</body></html>"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
