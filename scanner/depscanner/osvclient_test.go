package depscanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchVuln(t *testing.T) {
	t.Parallel()
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
			if err := json.NewEncoder(w).Encode(vuln); err != nil {
				t.Logf("encode vuln: %v", err)
			}
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
			if _, err := w.Write([]byte("not found")); err != nil {
				t.Logf("write body: %v", err)
			}
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
			if err := json.NewEncoder(w).Encode(Vulnerability{ID: "test"}); err != nil {
				t.Logf("encode: %v", err)
			}
		}))
		defer server.Close()

		client := NewOSVClient()
		client.baseURL = server.URL

		if _, err := client.FetchVuln(context.Background(), "test"); err != nil {
			t.Logf("FetchVuln: %v", err)
		}

		if receivedUA != "pci-dss-mcp/v1.0.0" {
			t.Errorf("User-Agent = %q, want pci-dss-mcp/v1.0.0", receivedUA)
		}
	})
}
