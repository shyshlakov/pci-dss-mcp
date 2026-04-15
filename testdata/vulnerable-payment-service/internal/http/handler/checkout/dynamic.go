package checkout

import (
	"html/template"
	"net/http"
)

func RenderCheckoutDynamic(w http.ResponseWriter, r *http.Request) {
	policy := buildPolicy(r)
	w.Header().Set("Content-Security-Policy", policy)
	tmpl := template.Must(template.New("dyn").Parse("<html><body>Pay</body></html>"))
	if err := tmpl.Execute(w, nil); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
	}
}

func buildPolicy(_ *http.Request) string { return "default-src 'self'" }
