package scriptscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// parseFuncBody parses Go source containing a single function and returns its body.
func parseFuncBody(t *testing.T, src string) *ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Body != nil {
			return fn.Body
		}
	}
	t.Fatal("no function declaration found in source")
	return nil
}

func TestDetectResponseType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
		want responseType
	}{
		{
			name: "json.NewEncoder",
			src: `package test
import "encoding/json"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}`,
			want: responseJSON,
		},
		{
			name: "json.Marshal",
			src: `package test
import "encoding/json"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(resp)
	w.Write(data)
}`,
			want: responseJSON,
		},
		{
			name: "json.MarshalIndent",
			src: `package test
import "encoding/json"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := json.MarshalIndent(resp, "", "  ")
	w.Write(data)
}`,
			want: responseJSON,
		},
		{
			name: "Content-Type application/json header",
			src: `package test
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}`,
			want: responseJSON,
		},
		{
			name: "template.Execute",
			src: `package test
import "html/template"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("page").Parse("<html></html>")
	tmpl.Execute(w, nil)
}`,
			want: responseHTML,
		},
		{
			name: "template.ExecuteTemplate",
			src: `package test
import "html/template"
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("").ParseFiles("page.html")
	tmpl.ExecuteTemplate(w, "page.html", nil)
}`,
			want: responseHTML,
		},
		{
			name: "Content-Type text/html header",
			src: `package test
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte("<html></html>"))
}`,
			want: responseHTML,
		},
		{
			name: "unknown - no indicators",
			src: `package test
import "net/http"
func handler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment form"))
}`,
			want: responseUnknown,
		},
		// Framework-specific JSON response methods.
		{
			name: "Gin_JSON_method",
			src: `package test
func handler(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}`,
			want: responseJSON,
		},
		{
			name: "Gin_IndentedJSON_method",
			src: `package test
func handler(c *gin.Context) {
	c.IndentedJSON(200, data)
}`,
			want: responseJSON,
		},
		{
			name: "Gin_SecureJSON_method",
			src: `package test
func handler(c *gin.Context) {
	c.SecureJSON(200, data)
}`,
			want: responseJSON,
		},
		{
			name: "Gin_PureJSON_method",
			src: `package test
func handler(c *gin.Context) {
	c.PureJSON(200, data)
}`,
			want: responseJSON,
		},
		{
			name: "Gin_AsciiJSON_method",
			src: `package test
func handler(c *gin.Context) {
	c.AsciiJSON(200, data)
}`,
			want: responseJSON,
		},
		{
			name: "Echo_JSONBlob_method",
			src: `package test
func handler(c echo.Context) error {
	return c.JSONBlob(200, blob)
}`,
			want: responseJSON,
		},
		{
			name: "Echo_JSONPretty_method",
			src: `package test
func handler(c echo.Context) error {
	return c.JSONPretty(200, data, "  ")
}`,
			want: responseJSON,
		},
		{
			name: "Echo_JSONP_method",
			src: `package test
func handler(c echo.Context) error {
	return c.JSONP(200, "callback", data)
}`,
			want: responseJSON,
		},
		// Framework-specific HTML response methods.
		{
			name: "Gin_HTML_method",
			src: `package test
func handler(c *gin.Context) {
	c.HTML(200, "template.html", data)
}`,
			want: responseHTML,
		},
		{
			name: "Echo_HTMLBlob_method",
			src: `package test
func handler(c echo.Context) error {
	return c.HTMLBlob(200, blob)
}`,
			want: responseHTML,
		},
		// Ambiguous framework methods should remain unknown.
		{
			name: "Gin_Render_method_ambiguous",
			src: `package test
func handler(c *gin.Context) {
	c.Render(200, render)
}`,
			want: responseUnknown,
		},
		// Existing stdlib detection unchanged.
		{
			name: "existing_json_Marshal_still_works",
			src: `package test
import "encoding/json"
func handler(w http.ResponseWriter, r *http.Request) {
	data, _ := json.Marshal(resp)
	w.Write(data)
}`,
			want: responseJSON,
		},
		{
			name: "existing_template_Execute_still_works",
			src: `package test
import "html/template"
func handler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.New("page").Parse("<html></html>")
	tmpl.Execute(w, nil)
}`,
			want: responseHTML,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := parseFuncBody(t, tt.src)
			got := detectResponseType(body)
			if got != tt.want {
				t.Errorf("detectResponseType() = %d, want %d", got, tt.want)
			}
		})
	}
}
