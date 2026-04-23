package triagescanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverMiddleware_FindsUseAndGroup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a file matching "router" path pattern with Use and Group calls.
	routerDir := filepath.Join(dir, "router")
	if err := os.MkdirAll(routerDir, 0755); err != nil {
		t.Fatal(err)
	}

	routerFile := filepath.Join(routerDir, "setup.go")
	src := `package router

import "github.com/gin-gonic/gin"

func Setup(r *gin.Engine) {
	r.Use(logMiddleware)
	api := r.Group("/api", authMiddleware)
	api.GET("/pay", handlePayment)
}
`
	if err := os.WriteFile(routerFile, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	cache := make(fileCache)
	evidence := discoverMiddleware(dir, cache)

	// Should find Use and Group middleware registrations.
	var foundUse, foundGroup bool
	for _, ev := range evidence {
		if ev.MethodName == "Use" {
			foundUse = true
			if len(ev.Args) == 0 || ev.Args[0] != "logMiddleware" {
				t.Errorf("Use: expected arg 'logMiddleware', got %v", ev.Args)
			}
		}
		if ev.MethodName == "Group" {
			foundGroup = true
		}
	}
	if !foundUse {
		t.Error("expected to find Use middleware registration")
	}
	if !foundGroup {
		t.Error("expected to find Group middleware registration")
	}
}

func TestDiscoverMiddleware_FiltersPathPatterns(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create file in "middleware" directory -- should be scanned.
	mwDir := filepath.Join(dir, "middleware")
	if err := os.MkdirAll(mwDir, 0755); err != nil {
		t.Fatal(err)
	}
	mwFile := filepath.Join(mwDir, "logging.go")
	mwSrc := `package middleware

func Install(r interface{}) {
	// r.Use(auditLogger)
}
`
	if err := os.WriteFile(mwFile, []byte(mwSrc), 0644); err != nil {
		t.Fatal(err)
	}

	// Create file NOT matching any pattern -- should NOT be scanned
	// (unless it imports HTTP framework, which it doesn't).
	utilDir := filepath.Join(dir, "util")
	if err := os.MkdirAll(utilDir, 0755); err != nil {
		t.Fatal(err)
	}
	utilFile := filepath.Join(utilDir, "helper.go")
	utilSrc := `package util

func helper() {}
`
	if err := os.WriteFile(utilFile, []byte(utilSrc), 0644); err != nil {
		t.Fatal(err)
	}

	cache := make(fileCache)
	_ = discoverMiddleware(dir, cache)

	// middleware/logging.go should be parsed into cache.
	found := false
	for k := range cache {
		if filepath.Base(k) == "logging.go" {
			found = true
		}
	}
	if !found {
		t.Error("expected middleware/logging.go to be scanned")
	}
}

func TestFindMiddlewareRegistrations(t *testing.T) {
	t.Parallel()
	src := `package main

func setup() {
	router.Use(logMiddleware)
	router.Use(corsMiddleware, csrfMiddleware)
	engine.Middleware(rateLimit)
	g := router.Group("/v1", authCheck)
}
`
	cache := make(fileCache)
	dir := t.TempDir()
	f := filepath.Join(dir, "setup.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := getParsedGoFile(cache, f)
	if err != nil {
		t.Fatal(err)
	}

	evidence := findMiddlewareRegistrations(pf.astFile, pf.fset, pf.lines)
	if len(evidence) < 3 {
		t.Fatalf("expected at least 3 middleware registrations, got %d", len(evidence))
	}

	// Verify first Use has correct arg.
	if evidence[0].MethodName != "Use" {
		t.Errorf("evidence[0].MethodName = %q, want 'Use'", evidence[0].MethodName)
	}
	if len(evidence[0].Args) == 0 || evidence[0].Args[0] != "logMiddleware" {
		t.Errorf("evidence[0].Args = %v, want ['logMiddleware']", evidence[0].Args)
	}
}

func TestFindRouteRegistrations(t *testing.T) {
	t.Parallel()
	src := `package main

func setup() {
	router.GET("/pay", handlePayment)
	http.HandleFunc("/checkout", checkoutHandler)
	mux.Post("/refund", refundHandler)
}
`
	cache := make(fileCache)
	dir := t.TempDir()
	f := filepath.Join(dir, "routes.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := getParsedGoFile(cache, f)
	if err != nil {
		t.Fatal(err)
	}

	routes := findRouteRegistrations(pf.astFile, pf.fset, pf.lines)
	if len(routes) != 3 {
		t.Fatalf("expected 3 route registrations, got %d", len(routes))
	}

	// First route should be GET with path /pay.
	if routes[0].MethodName != "GET" {
		t.Errorf("routes[0].MethodName = %q, want 'GET'", routes[0].MethodName)
	}
}

func TestExtractCallArgNames(t *testing.T) {
	t.Parallel()
	src := `package main

func setup() {
	r.Use(logMiddleware)
	r.Use(pkg.AuthMiddleware)
	r.Use(mfaRequired(handler))
	r.Use(func() {})
}
`
	cache := make(fileCache)
	dir := t.TempDir()
	f := filepath.Join(dir, "args.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	pf, err := getParsedGoFile(cache, f)
	if err != nil {
		t.Fatal(err)
	}

	evidence := findMiddlewareRegistrations(pf.astFile, pf.fset, pf.lines)
	if len(evidence) != 4 {
		t.Fatalf("expected 4 middleware Use calls, got %d", len(evidence))
	}

	// Ident: logMiddleware
	if evidence[0].Args[0] != "logMiddleware" {
		t.Errorf("arg[0] = %q, want 'logMiddleware'", evidence[0].Args[0])
	}

	// SelectorExpr: pkg.AuthMiddleware
	if evidence[1].Args[0] != "pkg.AuthMiddleware" {
		t.Errorf("arg[1] = %q, want 'pkg.AuthMiddleware'", evidence[1].Args[0])
	}

	// CallExpr: mfaRequired(handler)
	if evidence[2].Args[0] != "mfaRequired" {
		t.Errorf("arg[2] = %q, want 'mfaRequired'", evidence[2].Args[0])
	}

	// FuncLit: <expr>
	if evidence[3].Args[0] != "<expr>" {
		t.Errorf("arg[3] = %q, want '<expr>'", evidence[3].Args[0])
	}
}
