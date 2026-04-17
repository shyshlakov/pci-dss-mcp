package reportscanner

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestCursorRoundTrip(t *testing.T) {
	tt := []struct {
		name string
		in   cursorPayload
	}{
		{"full", cursorPayload{SID: "abc123def4567890", Off: 42, Tool: "generate_compliance_report"}},
		{"zero_off", cursorPayload{SID: "s1", Off: 0, Tool: "triage_findings"}},
		{"empty_tool", cursorPayload{SID: "s2", Off: 120, Tool: ""}},
		{"large_off", cursorPayload{SID: "deadbeefcafe0001", Off: 1_000_000, Tool: "scan_pan_data"}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := encodeCursor(tc.in)
			if err != nil {
				t.Fatalf("encodeCursor err: %v", err)
			}
			if enc == "" {
				t.Fatalf("encoded cursor must be non-empty")
			}
			dec, err := decodeCursor(enc)
			if err != nil {
				t.Fatalf("decodeCursor err: %v", err)
			}
			if !reflect.DeepEqual(dec, tc.in) {
				t.Fatalf("round-trip mismatch:\n got:  %+v\n want: %+v", dec, tc.in)
			}
		})
	}
}

func TestCursorEncode_UsesRawURLEncoding(t *testing.T) {
	enc, err := encodeCursor(cursorPayload{SID: "sid-x", Off: 1, Tool: "t"})
	if err != nil {
		t.Fatalf("encodeCursor err: %v", err)
	}
	if strings.ContainsAny(enc, "=+/") {
		t.Fatalf("raw-url-encoded cursor must not contain = + or /, got %q", enc)
	}
}

func TestCursorDecode_MalformedBase64(t *testing.T) {
	tt := []string{
		"not-base64-!@#",
		"====",
		"\x00\x01\x02",
	}
	for _, in := range tt {
		t.Run(in, func(t *testing.T) {
			_, err := decodeCursor(in)
			if err == nil {
				t.Fatalf("expected error for malformed base64, got nil")
			}
			if !strings.Contains(err.Error(), "cursor_malformed") {
				t.Fatalf("error must contain cursor_malformed, got %q", err.Error())
			}
		})
	}
}

func TestCursorDecode_MalformedJSON(t *testing.T) {
	bad := base64.RawURLEncoding.EncodeToString([]byte("{not json"))
	_, err := decodeCursor(bad)
	if err == nil {
		t.Fatalf("expected error for malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "cursor_malformed") {
		t.Fatalf("error must contain cursor_malformed, got %q", err.Error())
	}
}

func TestCursorDecode_MissingTool_OK(t *testing.T) {
	p := cursorPayload{SID: "sid-y", Off: 7, Tool: ""}
	enc, err := encodeCursor(p)
	if err != nil {
		t.Fatalf("encodeCursor err: %v", err)
	}
	dec, err := decodeCursor(enc)
	if err != nil {
		t.Fatalf("decodeCursor err: %v", err)
	}
	if dec.Tool != "" {
		t.Fatalf("empty Tool must round-trip as empty, got %q", dec.Tool)
	}
	if dec.SID != p.SID || dec.Off != p.Off {
		t.Fatalf("round-trip lost SID or Off: got %+v, want %+v", dec, p)
	}
}
