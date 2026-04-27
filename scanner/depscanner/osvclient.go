package depscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	defaultOSVBaseURL = "https://api.osv.dev"
	defaultUserAgent  = "pci-dss-mcp/v1.0.0"
)

type OSVClient struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		baseURL: defaultOSVBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		userAgent: defaultUserAgent,
	}
}

func (c *OSVClient) FetchVuln(ctx context.Context, id string) (*Vulnerability, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("create vulns request: %w", err)
	}
	httpReq.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("vulns request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close osv vulns response body", "id", id, "err", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vulns/%s: unexpected status %d", id, resp.StatusCode)
	}

	var vuln Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decode vulnerability %s: %w", id, err)
	}

	return &vuln, nil
}
