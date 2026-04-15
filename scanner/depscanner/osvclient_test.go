package depscanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestQueryBatch(t *testing.T) {
	t.Run("sends POST to /v1/querybatch with correct JSON body", func(t *testing.T) {
		var receivedBody QueryBatchRequest
		var receivedMethod string
		var receivedPath string
		var receivedContentType string
		var receivedUserAgent string

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedContentType = r.Header.Get("Content-Type")
			receivedUserAgent = r.Header.Get("User-Agent")

			body, _ := io.ReadAll(r.Body)
			json.Unmarshal(body, &receivedBody)

			resp := QueryBatchResponse{
				Results: []QueryResult{
					{Vulns: []VulnRef{{ID: "GHSA-1234", Modified: "2024-01-01"}}},
					{Vulns: nil},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		deps := []Dependency{
			{Path: "golang.org/x/net", Version: "v0.20.0", Line: 6},
			{Path: "github.com/gin-gonic/gin", Version: "v1.9.0", Line: 7},
		}

		resp, err := client.QueryBatch(context.Background(), deps)
		if err != nil {
			t.Fatalf("QueryBatch() error: %v", err)
		}

		if receivedMethod != "POST" {
			t.Errorf("method = %q, want POST", receivedMethod)
		}
		if receivedPath != "/v1/querybatch" {
			t.Errorf("path = %q, want /v1/querybatch", receivedPath)
		}
		if receivedContentType != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", receivedContentType)
		}
		if receivedUserAgent != "pci-dss-mcp/v1.0.0" {
			t.Errorf("User-Agent = %q, want pci-dss-mcp/v1.0.0", receivedUserAgent)
		}

		// Verify v-prefix is stripped per OSV requirement.
		if len(receivedBody.Queries) != 2 {
			t.Fatalf("queries count = %d, want 2", len(receivedBody.Queries))
		}
		if receivedBody.Queries[0].Version != "0.20.0" {
			t.Errorf("query[0].Version = %q, want %q (v-prefix stripped)", receivedBody.Queries[0].Version, "0.20.0")
		}
		if receivedBody.Queries[0].Package.Ecosystem != "Go" {
			t.Errorf("query[0].Package.Ecosystem = %q, want Go", receivedBody.Queries[0].Package.Ecosystem)
		}
		if receivedBody.Queries[0].Package.Name != "golang.org/x/net" {
			t.Errorf("query[0].Package.Name = %q, want golang.org/x/net", receivedBody.Queries[0].Package.Name)
		}
		if receivedBody.Queries[1].Version != "1.9.0" {
			t.Errorf("query[1].Version = %q, want %q (v-prefix stripped)", receivedBody.Queries[1].Version, "1.9.0")
		}

		// Verify response parsing.
		if resp == nil {
			t.Fatal("response is nil")
		}
		if len(resp.Results) != 2 {
			t.Fatalf("results count = %d, want 2", len(resp.Results))
		}
		if len(resp.Results[0].Vulns) != 1 {
			t.Fatalf("results[0].Vulns count = %d, want 1", len(resp.Results[0].Vulns))
		}
		if resp.Results[0].Vulns[0].ID != "GHSA-1234" {
			t.Errorf("results[0].Vulns[0].ID = %q, want GHSA-1234", resp.Results[0].Vulns[0].ID)
		}
	})

	t.Run("enforces timeout via parent context", func(t *testing.T) {
		// Use a channel to unblock the server handler when test completes.
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-done
		}))
		defer func() {
			close(done)
			server.Close()
		}()

		client := NewOSVClient()
		client.baseURL = server.URL

		deps := []Dependency{{Path: "example.com/mod", Version: "v1.0.0"}}

		// Use a short parent context — QueryBatch creates a child with min(parent, 5s).
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := client.QueryBatch(ctx, deps)
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "context") {
			t.Errorf("expected context error, got: %v", err)
		}
	})

	t.Run("returns error for non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		deps := []Dependency{{Path: "example.com/mod", Version: "v1.0.0"}}

		_, err := client.QueryBatch(context.Background(), deps)
		if err == nil {
			t.Fatal("expected error for 500 status")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("error should contain status code: %v", err)
		}
	})
}

func TestFetchVuln(t *testing.T) {
	t.Run("sends GET to /v1/vulns/{id} and returns full Vulnerability", func(t *testing.T) {
		var receivedMethod string
		var receivedPath string
		var receivedUserAgent string

		vuln := Vulnerability{
			ID:               "GHSA-test-1234",
			Summary:          "Test vulnerability in x/net",
			Aliases:          []string{"CVE-2024-1234"},
			DatabaseSpecific: DatabaseSpecific{Severity: "HIGH"},
			Affected: []Affected{
				{
					Package: AffectedPackage{Name: "golang.org/x/net", Ecosystem: "Go"},
					Ranges: []Range{
						{
							Type:   "SEMVER",
							Events: []Event{{Introduced: "0"}, {Fixed: "0.23.0"}},
						},
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedMethod = r.Method
			receivedPath = r.URL.Path
			receivedUserAgent = r.Header.Get("User-Agent")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(vuln)
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		result, err := client.FetchVuln(context.Background(), "GHSA-test-1234")
		if err != nil {
			t.Fatalf("FetchVuln() error: %v", err)
		}

		if receivedMethod != "GET" {
			t.Errorf("method = %q, want GET", receivedMethod)
		}
		if receivedPath != "/v1/vulns/GHSA-test-1234" {
			t.Errorf("path = %q, want /v1/vulns/GHSA-test-1234", receivedPath)
		}
		if receivedUserAgent != "pci-dss-mcp/v1.0.0" {
			t.Errorf("User-Agent = %q, want pci-dss-mcp/v1.0.0", receivedUserAgent)
		}

		if result.ID != "GHSA-test-1234" {
			t.Errorf("ID = %q, want GHSA-test-1234", result.ID)
		}
		if result.Summary != "Test vulnerability in x/net" {
			t.Errorf("Summary = %q, want 'Test vulnerability in x/net'", result.Summary)
		}
		if len(result.Aliases) != 1 || result.Aliases[0] != "CVE-2024-1234" {
			t.Errorf("Aliases = %v, want [CVE-2024-1234]", result.Aliases)
		}
	})

	t.Run("returns error for non-200 status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("not found"))
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		_, err := client.FetchVuln(context.Background(), "GHSA-nonexistent")
		if err == nil {
			t.Fatal("expected error for 404 status")
		}
		if !strings.Contains(err.Error(), "404") {
			t.Errorf("error should contain status code: %v", err)
		}
	})

	t.Run("User-Agent header is pci-dss-mcp/v1.0.0", func(t *testing.T) {
		var receivedUA string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedUA = r.Header.Get("User-Agent")
			json.NewEncoder(w).Encode(Vulnerability{ID: "test"})
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		client.FetchVuln(context.Background(), "test")

		if receivedUA != "pci-dss-mcp/v1.0.0" {
			t.Errorf("User-Agent = %q, want pci-dss-mcp/v1.0.0", receivedUA)
		}
	})
}
