package checkout

import (
	"html/template"
	"net/http"
)

func RenderCheckoutEval(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy", "script-src 'unsafe-eval'")
	tmpl := template.Must(template.New("eval").Parse("<html><body>Pay</body></html>"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}
