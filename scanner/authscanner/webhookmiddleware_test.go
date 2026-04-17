package authscanner

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestArgLooksLikeSignatureMiddleware(t *testing.T) {
	tt := []struct {
		name string
		expr string
		want bool
	}{
		{"VerifyHMAC ident", `VerifyHMAC`, true},
		{"VerifySignature ident", `VerifySignature`, true},
		{"WebhookAuth ident", `WebhookAuth`, true},
		{"hmac.Verify selector", `hmac.Verify`, true},
		{"signature.Middleware selector", `signature.Middleware`, true},
		{"verifyHmacMW lowercase", `verifyHmacMW`, true},
		{"Auth alone matches", `Auth`, true},
		{"LoggerMiddleware no match", `LoggerMiddleware`, false},
		{"RequestID no match", `RequestID`, false},
		{"CORS no match", `CORS`, false},
		{"RateLimit no match", `RateLimit`, false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			expr, err := parser.ParseExpr(tc.expr)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.expr, err)
			}
			got := argLooksLikeSignatureMiddleware(expr)
			if got != tc.want {
				t.Errorf("argLooksLikeSignatureMiddleware(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestResetWebhookMiddlewareCache(t *testing.T) {
	ResetWebhookMiddlewareCache()
	dir := t.TempDir()
	src := `package x
type Router struct{}
func (*Router) Use(h any) {}
func (*Router) HandleFunc(p string, h any) {}
func InstallRoutes(r *Router) {
	r.Use(VerifyHMAC)
	r.HandleFunc("/x", OnEvent)
}
func VerifyHMAC(h any) any { return h }
func OnEvent() {}
`
	if err := os.WriteFile(filepath.Join(dir, "router.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	HasSignatureMiddlewareCoverage(filepath.Join(dir, "router.go"), "OnEvent")
	webhookCacheMu.Lock()
	cachedBefore := len(webhookCachePackages)
	webhookCacheMu.Unlock()
	if cachedBefore == 0 {
		t.Fatalf("expected cache populated after first call")
	}
	ResetWebhookMiddlewareCache()
	webhookCacheMu.Lock()
	cachedAfter := len(webhookCachePackages)
	webhookCacheMu.Unlock()
	if cachedAfter != 0 {
		t.Errorf("expected cache empty after reset, got %d entries", cachedAfter)
	}
}

func TestHasSignatureMiddlewareCoverageCrossFile(t *testing.T) {
	ResetWebhookMiddlewareCache()
	dir := t.TempDir()
	router := `package x
type Router struct{}
func (*Router) Use(h any) {}
func (*Router) HandleFunc(p string, h any) {}
func InstallRoutes(r *Router) {
	r.Use(VerifyWebhookSignature)
	r.HandleFunc("/x", OnPaymentEvent)
}
func VerifyWebhookSignature(h any) any { return h }
`
	handler := `package x
import "net/http"
func OnPaymentEvent(w http.ResponseWriter, r *http.Request) {}
`
	if err := os.WriteFile(filepath.Join(dir, "router.go"), []byte(router), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(handler), 0o644); err != nil {
		t.Fatal(err)
	}
	got := HasSignatureMiddlewareCoverage(filepath.Join(dir, "handler.go"), "OnPaymentEvent")
	if !got {
		t.Errorf("expected coverage match via VerifyWebhookSignature middleware on same-package router")
	}
}

func TestHasSignatureMiddlewareCoverageNoMatch(t *testing.T) {
	ResetWebhookMiddlewareCache()
	dir := t.TempDir()
	src := `package x
type Router struct{}
func (*Router) Use(h any) {}
func (*Router) HandleFunc(p string, h any) {}
func InstallRoutes(r *Router) {
	r.Use(LoggerMW)
	r.HandleFunc("/x", OnEvent)
}
func LoggerMW(h any) any { return h }
func OnEvent() {}
`
	if err := os.WriteFile(filepath.Join(dir, "router.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got := HasSignatureMiddlewareCoverage(filepath.Join(dir, "router.go"), "OnEvent")
	if got {
		t.Errorf("expected no coverage; LoggerMW must not match signature predicate")
	}
}

func TestHasSignatureMiddlewareWrapper(t *testing.T) {
	ResetWebhookMiddlewareCache()
	dir := t.TempDir()
	src := `package x
import "net/http"
func Install(mux *http.ServeMux) {
	mux.HandleFunc("/x", VerifyWebhookSignatureMiddleware(OnEvent))
}
func VerifyWebhookSignatureMiddleware(h http.HandlerFunc) http.HandlerFunc { return h }
func OnEvent(w http.ResponseWriter, r *http.Request) {}
`
	if err := os.WriteFile(filepath.Join(dir, "router.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	got := HasSignatureMiddlewareCoverage(filepath.Join(dir, "router.go"), "OnEvent")
	if !got {
		t.Errorf("expected wrapper-based coverage via VerifyWebhookSignatureMiddleware wrapper")
	}
}

func TestSignatureIsTrustedMiddlewarePackage(t *testing.T) {
	tt := []struct {
		path string
		want bool
	}{
		{"github.com/example/webhook", true},
		{"github.com/example/signature", true},
		{"github.com/example/hmac", true},
		{"github.com/example/logging", false},
		{"github.com/example/app", false},
	}
	for _, tc := range tt {
		got := signatureIsTrustedMiddlewarePackage(tc.path)
		if got != tc.want {
			t.Errorf("signatureIsTrustedMiddlewarePackage(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
	_ = token.NoPos
}
