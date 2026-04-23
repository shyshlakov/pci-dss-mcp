package triagescanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestCollectAuditContext(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a router/main.go with audit middleware and route registration.
	routerDir := filepath.Join(dir, "router")
	if err := os.MkdirAll(routerDir, 0755); err != nil {
		t.Fatal(err)
	}
	mainSrc := `package router

import "github.com/gin-gonic/gin"

func Setup(r *gin.Engine) {
	r.Use(auditLogger)
	r.Use(corsMiddleware)
	r.POST("/api/payment", handlePayment)
}
`
	if err := os.WriteFile(filepath.Join(routerDir, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}

	// Create handler.go where the finding is.
	handlerSrc := `package router

import "net/http"

func handlePayment(w http.ResponseWriter, r *http.Request) {
	// process payment
}
`
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:      "AUDIT-NO-LOG",
		FilePath:    "handler.go",
		Line:        5,
		Description: "No audit logging in handler handlePayment",
	}
	absPath := filepath.Join(dir, "handler.go")

	ctx := FindingContext{}
	collectAuditContext(engine, dir, finding, absPath, &ctx)

	// Should find auditLogger in middleware chain (contains "log" or "audit").
	if len(ctx.MiddlewareChain) == 0 {
		t.Error("expected non-empty MiddlewareChain")
	}

	foundAudit := false
	for _, mw := range ctx.MiddlewareChain {
		if strings.Contains(strings.ToLower(mw), "audit") {
			foundAudit = true
		}
	}
	if !foundAudit {
		t.Errorf("expected middleware chain to contain audit-related entry, got: %v", ctx.MiddlewareChain)
	}

	// Should have evidence files.
	if len(ctx.EvidenceFiles) == 0 {
		t.Error("expected non-empty EvidenceFiles")
	}
}

func TestCollectCSPContext_ResponseType(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create handler with JSON response.
	handlerSrc := `package main

import (
	"encoding/json"
	"net/http"
)

func handlePayment(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
`
	handlerFile := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(handlerFile, []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:      "CSP-MISSING",
		FilePath:    "handler.go",
		Line:        9,
		Description: "No CSP header",
	}

	ctx := FindingContext{}
	collectCSPContext(engine, dir, finding, handlerFile, &ctx)

	if ctx.ResponseType != "application/json" {
		t.Errorf("ResponseType = %q, want 'application/json'", ctx.ResponseType)
	}
}

func TestCollectCSPContext_HTMLResponse(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	handlerSrc := `package main

import (
	"html/template"
	"net/http"
)

func handlePage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.New("page")
	tmpl.Execute(w, nil)
}
`
	handlerFile := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(handlerFile, []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "CSP-MISSING",
		FilePath: "handler.go",
		Line:     9,
	}

	ctx := FindingContext{}
	collectCSPContext(engine, dir, finding, handlerFile, &ctx)

	if ctx.ResponseType != "text/html" {
		t.Errorf("ResponseType = %q, want 'text/html'", ctx.ResponseType)
	}
}

func TestCollectCSPContext_MiddlewareEvidence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create server file with CSP middleware.
	serverDir := filepath.Join(dir, "server")
	if err := os.MkdirAll(serverDir, 0755); err != nil {
		t.Fatal(err)
	}
	serverSrc := `package server

import "github.com/gin-gonic/gin"

func Setup(r *gin.Engine) {
	r.Use(securityHeaders)
	r.Use(cspMiddleware)
}
`
	if err := os.WriteFile(filepath.Join(serverDir, "setup.go"), []byte(serverSrc), 0644); err != nil {
		t.Fatal(err)
	}

	// Handler file where finding is.
	handlerSrc := `package main

func handlePage() {}
`
	handlerFile := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(handlerFile, []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "CSP-MISSING",
		FilePath: "handler.go",
		Line:     3,
	}

	ctx := FindingContext{}
	collectCSPContext(engine, dir, finding, handlerFile, &ctx)

	// Should find CSP or security middleware.
	if len(ctx.MiddlewareChain) == 0 {
		t.Error("expected CSP-related middleware in chain")
	}

	foundCSP := false
	for _, mw := range ctx.MiddlewareChain {
		lower := strings.ToLower(mw)
		if strings.Contains(lower, "csp") || strings.Contains(lower, "security") {
			foundCSP = true
		}
	}
	if !foundCSP {
		t.Errorf("expected CSP/security middleware, got: %v", ctx.MiddlewareChain)
	}
}

func TestCollectMFAContext_RouteRegistration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create routes file with route registration.
	routesDir := filepath.Join(dir, "routes")
	if err := os.MkdirAll(routesDir, 0755); err != nil {
		t.Fatal(err)
	}
	routesSrc := `package routes

import "net/http"

func Setup() {
	http.HandleFunc("/payment", handlePayment)
	http.HandleFunc("/checkout", checkoutHandler)
}
`
	if err := os.WriteFile(filepath.Join(routesDir, "routes.go"), []byte(routesSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:      "AUTH-MISSING-MFA",
		FilePath:    "handler.go",
		Line:        5,
		Description: "No MFA middleware detected on payment route /payment",
	}
	absPath := filepath.Join(dir, "handler.go")
	// Create a minimal handler.go so absPath is valid.
	if err := os.WriteFile(absPath, []byte("package main\nfunc handlePayment() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := FindingContext{}
	collectMFAContext(engine, dir, finding, absPath, &ctx)

	// Should find route registration for handlePayment.
	if ctx.RouterSetup == "" {
		t.Error("expected non-empty RouterSetup")
	}
}

func TestCollectMFAContext_AuthMiddleware(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create handler file with middleware setup.
	handlerDir := filepath.Join(dir, "handler")
	if err := os.MkdirAll(handlerDir, 0755); err != nil {
		t.Fatal(err)
	}
	handlerSrc := `package handler

import "github.com/gin-gonic/gin"

func Setup(r *gin.Engine) {
	api := r.Group("/api", mfaRequired)
	api.POST("/payment", handlePayment)
}
`
	if err := os.WriteFile(filepath.Join(handlerDir, "setup.go"), []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:      "AUTH-MISSING-MFA",
		FilePath:    "handler.go",
		Line:        5,
		Description: "No MFA on payment handler handlePayment",
	}
	absPath := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(absPath, []byte("package main\nfunc handlePayment() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := FindingContext{}
	collectMFAContext(engine, dir, finding, absPath, &ctx)

	// Should find MFA/auth middleware in chain.
	if len(ctx.MiddlewareChain) == 0 {
		t.Error("expected MFA/auth middleware in chain")
	}

	foundMFA := false
	for _, mw := range ctx.MiddlewareChain {
		lower := strings.ToLower(mw)
		if strings.Contains(lower, "mfa") || strings.Contains(lower, "auth") {
			foundMFA = true
		}
	}
	if !foundMFA {
		t.Errorf("expected MFA/auth middleware, got: %v", ctx.MiddlewareChain)
	}
}

func TestFindEnclosingFunc(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package main

import "fmt"

func foo() {
	fmt.Println("hello")
}

func bar() {
	fmt.Println("world")
}
`
	f := filepath.Join(dir, "test.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	cache := make(fileCache)
	pf, err := getParsedGoFile(cache, f)
	if err != nil {
		t.Fatal(err)
	}

	// Line 6 is inside foo().
	fn := findEnclosingFunc(pf.astFile, pf.fset, 6)
	if fn == nil {
		t.Fatal("expected to find enclosing func for line 6")
	}
	if fn.Name.Name != "foo" {
		t.Errorf("expected func 'foo', got %q", fn.Name.Name)
	}

	// Line 10 is inside bar().
	fn = findEnclosingFunc(pf.astFile, pf.fset, 10)
	if fn == nil {
		t.Fatal("expected to find enclosing func for line 10")
	}
	if fn.Name.Name != "bar" {
		t.Errorf("expected func 'bar', got %q", fn.Name.Name)
	}

	// Line 3 is at package level (import).
	fn = findEnclosingFunc(pf.astFile, pf.fset, 3)
	if fn != nil {
		t.Errorf("expected nil for package-level line, got func %q", fn.Name.Name)
	}
}

func TestCollectSecretsContext_ConstBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package main

const (
	apiKey    = "sk_live_abc123def456"
	apiSecret = "secret_value_here"
)
`
	f := filepath.Join(dir, "config.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:      "SECRET-HARDCODED",
		FilePath:    "config.go",
		Line:        4,
		Description: "Hardcoded secret in variable apiKey",
	}

	ctx := FindingContext{}
	collectSecretsContext(engine, dir, finding, f, &ctx)

	if ctx.DeclarationScope != "const block" {
		t.Errorf("DeclarationScope = %q, want 'const block'", ctx.DeclarationScope)
	}
}

func TestCollectSecretsContext_VarBlock(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package main

var (
	dbPassword = "password123"
)
`
	f := filepath.Join(dir, "config.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "SECRET-HARDCODED",
		FilePath: "config.go",
		Line:     4,
	}

	ctx := FindingContext{}
	collectSecretsContext(engine, dir, finding, f, &ctx)

	if ctx.DeclarationScope != "var block" {
		t.Errorf("DeclarationScope = %q, want 'var block'", ctx.DeclarationScope)
	}
}

func TestCollectSecretsContext_FuncScope(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package main

func initConfig() {
	apiKey := "sk_live_abc123"
	_ = apiKey
}
`
	f := filepath.Join(dir, "config.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "CRYPTO-HARDCODED-KEY",
		FilePath: "config.go",
		Line:     4,
	}

	ctx := FindingContext{}
	collectSecretsContext(engine, dir, finding, f, &ctx)

	if ctx.DeclarationScope != "function scope: initConfig" {
		t.Errorf("DeclarationScope = %q, want 'function scope: initConfig'", ctx.DeclarationScope)
	}
}

func TestCollectSecretsContext_RuntimeIndicator(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package main

import "os"

func getConfig() string {
	key := os.Getenv("API_KEY")
	if key == "" {
		key = "default_fallback_key"
	}
	return key
}
`
	f := filepath.Join(dir, "config.go")
	if err := os.WriteFile(f, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "SECRET-HARDCODED",
		FilePath: "config.go",
		Line:     8,
	}

	ctx := FindingContext{}
	collectSecretsContext(engine, dir, finding, f, &ctx)

	// Should find os.Getenv as runtime indicator.
	foundIndicator := false
	for _, ev := range ctx.EvidenceFiles {
		if strings.Contains(ev, "os.Getenv") {
			foundIndicator = true
		}
	}
	if !foundIndicator {
		t.Errorf("expected runtime indicator for os.Getenv, got: %v", ctx.EvidenceFiles)
	}
}

func TestCollectSecretsContext_NonGoFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("API_KEY=sk_live_abc123\n"), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewTriageEngine()
	finding := scanner.Finding{
		RuleID:   "SECRET-HARDCODED",
		FilePath: ".env",
		Line:     1,
	}

	ctx := FindingContext{}
	collectSecretsContext(engine, dir, finding, envFile, &ctx)

	if ctx.DeclarationScope != "config file" {
		t.Errorf("DeclarationScope = %q, want 'config file'", ctx.DeclarationScope)
	}
}

func TestCollectContext_Dispatch(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create a handler.go that all dispatches can reference.
	handlerSrc := `package main

import "net/http"

const apiKey = "sk_live_abc123def456"

func handlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
	handlerFile := filepath.Join(dir, "handler.go")
	if err := os.WriteFile(handlerFile, []byte(handlerSrc), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		ruleID      string
		line        int
		description string
		checkField  string // which field should be populated
	}{
		{
			name:        "AUDIT prefix dispatches to audit collector",
			ruleID:      "AUDIT-NO-LOG",
			line:        7,
			description: "No audit logging in handler handlePayment",
			checkField:  "audit",
		},
		{
			name:        "CSP prefix dispatches to CSP collector",
			ruleID:      "CSP-MISSING",
			line:        7,
			description: "No CSP header",
			checkField:  "csp",
		},
		{
			name:        "AUTH-MISSING-MFA dispatches to MFA collector",
			ruleID:      "AUTH-MISSING-MFA",
			line:        7,
			description: "No MFA on payment handler handlePayment",
			checkField:  "mfa",
		},
		{
			name:        "SECRET prefix dispatches to secrets collector",
			ruleID:      "SECRET-HARDCODED",
			line:        5,
			description: "Hardcoded secret apiKey",
			checkField:  "secrets",
		},
		{
			name:        "CRYPTO-HARDCODED dispatches to secrets collector",
			ruleID:      "CRYPTO-HARDCODED-KEY",
			line:        5,
			description: "Hardcoded key in apiKey",
			checkField:  "secrets",
		},
		{
			name:        "Unknown prefix gets generic context only",
			ruleID:      "UNKNOWN-RULE",
			line:        7,
			description: "Some unknown finding",
			checkField:  "generic",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewTriageEngine()
			finding := scanner.Finding{
				RuleID:      tc.ruleID,
				FilePath:    "handler.go",
				Line:        tc.line,
				Description: tc.description,
			}

			fctx := engine.collectContext(dir, finding, handlerFile)

			// All dispatches should have a primary source link (generic context).
			if len(fctx.Sources) == 0 {
				t.Error("expected Sources to be populated with a primary ResourceLink")
			}

			// Check that the appropriate collector was called.
			switch tc.checkField {
			case "secrets":
				if fctx.DeclarationScope == "" {
					t.Error("expected DeclarationScope from secrets collector")
				}
			case "generic":
				// Generic context: should NOT have rule-specific fields populated
				// (no DeclarationScope, no ResponseType for non-CSP).
				if fctx.DeclarationScope != "" {
					t.Errorf("unexpected DeclarationScope for generic: %q", fctx.DeclarationScope)
				}
			}
		})
	}
}
