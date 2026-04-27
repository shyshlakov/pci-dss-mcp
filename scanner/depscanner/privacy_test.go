package depscanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type loggedRequest struct {
	Method   string
	Path     string
	RawQuery string
	Host     string
	Body     []byte
}

type osvEntry struct {
	id         string
	pkg        string
	fixedAtVer string
}

func defaultGoJoseEntry() osvEntry {
	return osvEntry{
		id:         "GHSA-test-go-jose",
		pkg:        "github.com/go-jose/go-jose/v4",
		fixedAtVer: "v4.1.4",
	}
}

func buildOSVZip(t *testing.T, entries ...osvEntry) []byte {
	t.Helper()

	if len(entries) == 0 {
		entries = []osvEntry{defaultGoJoseEntry()}
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		entry := map[string]any{
			"id":      e.id,
			"summary": "test advisory for " + e.pkg,
			"aliases": []string{},
			"affected": []map[string]any{
				{
					"package": map[string]string{
						"name":      e.pkg,
						"ecosystem": "Go",
					},
					"ranges": []map[string]any{
						{
							"type": "SEMVER",
							"events": []map[string]string{
								{"introduced": "0"},
								{"fixed": e.fixedAtVer},
							},
						},
					},
				},
			},
		}
		data, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal osv entry: %v", err)
		}
		w, err := zw.Create(e.id + ".json")
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func buildMinimalGoOSVZip(t *testing.T) []byte {
	t.Helper()
	return buildOSVZip(t, defaultGoJoseEntry())
}

func newRecordingOSVServer(t *testing.T) (*httptest.Server, *[]loggedRequest, *sync.Mutex) {
	t.Helper()

	var requests []loggedRequest
	var mu sync.Mutex
	zipBody := buildMinimalGoOSVZip(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, rerr := io.ReadAll(r.Body)
		if rerr != nil {
			t.Logf("server read body: %v", rerr)
		}
		mu.Lock()
		requests = append(requests, loggedRequest{
			Method:   r.Method,
			Path:     r.URL.Path,
			RawQuery: r.URL.RawQuery,
			Host:     r.Host,
			Body:     body,
		})
		mu.Unlock()

		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/Go/all.zip") {
			w.Header().Set("ETag", `"test-etag-1234"`)
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Content-Type", "application/zip")
			if _, werr := w.Write(zipBody); werr != nil {
				t.Logf("server write zip: %v", werr)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	return srv, &requests, &mu
}

func fixturePath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatalf("resolve fixture path: %v", err)
	}
	return p
}

func TestNetTrafficZeroQueryBatch(t *testing.T) {
	srv, requests, mu := newRecordingOSVServer(t)
	defer srv.Close()

	t.Setenv("OSV_BASE_URL", srv.URL)
	t.Setenv("PCI_MCP_CACHE_DIR", t.TempDir())

	ctx := context.Background()
	s := New()

	if _, err := s.Scan(ctx, fixturePath(t)); err != nil {
		t.Logf("first scan returned err (RED state expected): %v", err)
	}

	fixtureModuleFragments := []string{
		"go-jose",
		"golang.org/x/net",
		"golang.org/x/crypto",
		"gin-gonic/gin",
		"sirupsen/logrus",
	}

	mu.Lock()
	countAfterFirst := len(*requests)
	getCount := 0
	for _, req := range *requests {
		if req.Method == http.MethodPost && strings.Contains(req.Path, "/v1/querybatch") {
			t.Errorf("UNEXPECTED POST to %s, privacy regression!", req.Path)
		}
		if bytes.Contains(req.Body, []byte(`"package"`)) || bytes.Contains(req.Body, []byte(`"version"`)) {
			t.Errorf("request body contains package/version JSON, module-name leak!")
		}
		urlSurface := []byte(req.Path + "?" + req.RawQuery)
		for _, frag := range fixtureModuleFragments {
			fragB := []byte(frag)
			if bytes.Contains(req.Body, fragB) {
				t.Errorf("request body to %s leaked module-name fragment %q", req.Path, frag)
			}
			if bytes.Contains(urlSurface, fragB) {
				t.Errorf("request URL %s?%s leaked module-name fragment %q", req.Path, req.RawQuery, frag)
			}
		}
		if req.Method == http.MethodGet && strings.Contains(req.Path, "/Go/all.zip") {
			getCount++
		}
	}
	mu.Unlock()

	if getCount > 1 {
		t.Errorf("expected at most one GET to /Go/all.zip, got %d", getCount)
	}
	if countAfterFirst == 0 {
		t.Errorf("expected at least one recorded request to httptest server, got 0; OSV_BASE_URL not honored")
	}

	if _, err := s.Scan(ctx, fixturePath(t)); err != nil {
		t.Logf("second scan returned err (RED state expected): %v", err)
	}

	mu.Lock()
	delta := len(*requests) - countAfterFirst
	mu.Unlock()
	if delta != 0 {
		t.Errorf("subsequent in-TTL scan made %d outbound requests; want 0", delta)
	}
}

func TestQueryBatchSymbolDeleted(t *testing.T) {
	t.Parallel()

	client := NewOSVClient()
	typ := reflect.TypeOf(client)
	if _, ok := typ.MethodByName("QueryBatch"); ok {
		t.Errorf("OSVClient.QueryBatch must be deleted in 20.4 (privacy regression vector)")
	}
}

func TestOSVBaseURLOverride(t *testing.T) {
	srv, requests, mu := newRecordingOSVServer(t)
	defer srv.Close()

	t.Setenv("OSV_BASE_URL", srv.URL)
	t.Setenv("PCI_MCP_CACHE_DIR", t.TempDir())

	ctx := context.Background()
	s := New()

	if _, err := s.Scan(ctx, fixturePath(t)); err != nil {
		t.Logf("scan returned err (RED state expected): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	wantHost := srv.Listener.Addr().String()
	matched := false
	for _, req := range *requests {
		if req.Host == wantHost {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("no recorded request matched OSV_BASE_URL host %q; got %d requests, none routed to httptest server", wantHost, len(*requests))
	}
}
