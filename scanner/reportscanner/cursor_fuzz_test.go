package reportscanner

import (
	"encoding/base64"
	"testing"
)

func FuzzCursorDecode(f *testing.F) {
	validSeed, _ := encodeCursor(cursorPayload{SID: "abc123def4567890", Off: 42, Tool: "generate_compliance_report"})
	f.Add(validSeed)
	f.Add("")
	f.Add("not-base64-!@#")
	f.Add("====")
	f.Add("\x00\x01\x02")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("{not json")))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("{}")))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("null")))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte("[]")))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"sid":"","off":-1,"tool":""}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"sid":"x","off":9223372036854775807,"tool":"t"}`)))
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"sid":"` + string(make([]byte, 4096)) + `","off":0}`)))

	f.Fuzz(func(t *testing.T, s string) {
		p, err := decodeCursor(s)
		if err != nil {
			return
		}
		reEnc, reErr := encodeCursor(p)
		if reErr != nil {
			t.Fatalf("encodeCursor failed on round-trip of decoded payload %+v: %v", p, reErr)
		}
		p2, err2 := decodeCursor(reEnc)
		if err2 != nil {
			t.Fatalf("re-decode of re-encoded payload failed: %v (first payload %+v, reEnc %q)", err2, p, reEnc)
		}
		if p2.SID != p.SID || p2.Off != p.Off || p2.Tool != p.Tool {
			t.Fatalf("round-trip drift:\n first:  %+v\n second: %+v", p, p2)
		}
	})
}
