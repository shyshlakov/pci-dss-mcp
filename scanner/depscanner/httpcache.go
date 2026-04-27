package depscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

type cacheMeta struct {
	ETag         string `json:"etag"`
	LastModified string `json:"last_modified"`
}

func loadMeta(path string) (cacheMeta, error) {
	data, err := os.ReadFile(path + ".meta.json")
	if err != nil {
		return cacheMeta{}, err
	}
	var m cacheMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return cacheMeta{}, fmt.Errorf("parse cache meta: %w", err)
	}
	return m, nil
}

func saveMeta(path string, m cacheMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal cache meta: %w", err)
	}
	return os.WriteFile(path+".meta.json", data, 0o644)
}

func conditionalGet(ctx context.Context, url string, m cacheMeta) (*http.Response, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("conditional GET: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusNotModified:
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close 304 body", "err", cerr)
		}
		return nil, false, nil
	case http.StatusOK:
		return resp, true, nil
	default:
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close non-200 body", "err", cerr)
		}
		return nil, false, fmt.Errorf("conditional GET: unexpected status %d", resp.StatusCode)
	}
}
