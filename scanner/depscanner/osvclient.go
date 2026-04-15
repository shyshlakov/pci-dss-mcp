package depscanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	defaultOSVBaseURL = "https://api.osv.dev"
	queryBatchTimeout = 5 * time.Second
	defaultUserAgent  = "pci-dss-mcp/v1.0.0"
)

// OSVClient queries the OSV.dev vulnerability database.
type OSVClient struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
}

// NewOSVClient creates a new OSV API client with default settings.
// The HTTP client has a 10s default timeout; querybatch uses its own 5s context.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		baseURL: defaultOSVBaseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		userAgent: defaultUserAgent,
	}
}

// QueryBatch sends a batch of dependency queries to POST /v1/querybatch.
// It creates a child context with 5s timeout per DEP-02.
// Versions are stripped of the "v" prefix per OSV convention (Pitfall 1).
func (c *OSVClient) QueryBatch(ctx context.Context, deps []Dependency) (*QueryBatchResponse, error) {
	// Build request with v-prefix stripped per OSV requirement.
	req := QueryBatchRequest{
		Queries: make([]Query, len(deps)),
	}
	for i, dep := range deps {
		req.Queries[i] = Query{
			Package: QueryPackage{
				Name:      dep.Path,
				Ecosystem: "Go",
			},
			Version: strings.TrimPrefix(dep.Version, "v"),
		}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal querybatch request: %w", err)
	}

	// Create 5s timeout context as child of passed context.
	queryCtx, cancel := context.WithTimeout(ctx, queryBatchTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(queryCtx, http.MethodPost, c.baseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create querybatch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querybatch request: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Warn("close osv querybatch response body", "err", cerr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("querybatch: unexpected status %d", resp.StatusCode)
	}

	var result QueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode querybatch response: %w", err)
	}

	return &result, nil
}

// FetchVuln fetches full vulnerability details from GET /v1/vulns/{id}.
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
