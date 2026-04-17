package reportscanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type cursorPayload struct {
	SID  string `json:"sid"`
	Off  int    `json:"off"`
	Tool string `json:"tool,omitempty"`
}

func encodeCursor(p cursorPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("cursor_malformed: marshal: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeCursor(s string) (cursorPayload, error) {
	var p cursorPayload
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return p, fmt.Errorf("cursor_malformed: base64: %w", err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("cursor_malformed: json: %w", err)
	}
	return p, nil
}
