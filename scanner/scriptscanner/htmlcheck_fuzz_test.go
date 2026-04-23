package scriptscanner

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzScriptScannerHTML(f *testing.F) {
	f.Add([]byte(""))
	f.Add([]byte("<html></html>"))
	f.Add([]byte("<script src=\"x.js\"></script>"))
	f.Add([]byte("<script>alert(1)</script>"))
	f.Add([]byte("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\">"))
	f.Add([]byte("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'unsafe-inline' 'unsafe-eval'\">"))
	f.Add([]byte("<input name=\"card_number\">"))
	f.Add([]byte("<!-- <!-- nested --> -->"))
	f.Add([]byte("<![CDATA[ raw ]]>"))
	f.Add([]byte("<script src=\""))
	f.Add([]byte("<script integrity=\"sha384-\"></script>"))
	f.Add([]byte("<script nonce=\"\x00\x01\"></script>"))
	f.Add([]byte("\x00\x01\x02\x03"))
	f.Add([]byte("<script src=\"x\" integrity=\"\t\r\n\"></script>"))
	f.Add([]byte("<form action=\"/checkout\"><input type=\"password\" name=\"cvv\"></form>"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.html")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		s := &ScriptScanner{}
		_, _, _ = s.scanHTMLFile(path)
		_ = parseCSP(string(data))
	})
}
