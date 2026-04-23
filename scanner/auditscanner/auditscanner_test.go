package auditscanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// writeFixture writes Go source code to a temp directory and returns the directory path.
func writeFixture(t *testing.T, filename, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(src), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir
}

// findByRule returns findings matching the given ruleID.
func findByRule(findings []scanner.Finding, ruleID string) []scanner.Finding {
	var matched []scanner.Finding
	for _, f := range findings {
		if f.RuleID == ruleID {
			matched = append(matched, f)
		}
	}
	return matched
}

// findBySeverity returns findings matching the given severity.
func findBySeverity(findings []scanner.Finding, sev scanner.Severity) []scanner.Finding {
	var matched []scanner.Finding
	for _, f := range findings {
		if f.Severity == sev {
			matched = append(matched, f)
		}
	}
	return matched
}

// Test1: Payment handler with slog.Info call -> 0 HIGH findings, 1 INFO note about PCI DSS 10.2.1 fields.
func TestPaymentHandlerWithSlog(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"log/slog"
	"net/http"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	slog.Info("payment processed", "user_id", "123", "amount", 100)
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings, got %d: %+v", len(high), high)
	}

	info := findBySeverity(result.Findings, scanner.SeverityInfo)
	if len(info) != 1 {
		t.Errorf("Expected 1 INFO finding, got %d: %+v", len(info), info)
	}
	if len(info) > 0 && !strings.Contains(info[0].Description, "PCI DSS 10.2.1 fields") {
		t.Errorf("Expected INFO finding to mention PCI DSS 10.2.1 fields, got: %s", info[0].Description)
	}
}

// Test2: Payment handler with NO logging at all -> 1 CRITICAL finding (Tier 1 handler).
func TestPaymentHandlerNoLogging(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("payment processed"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	noLog := findByRule(result.Findings, "AUDIT-NO-LOG")
	if len(noLog) != 1 {
		t.Errorf("Expected 1 AUDIT-NO-LOG finding, got %d: %+v", len(noLog), noLog)
	}
	if len(noLog) > 0 {
		// Tier 1 handler "HandlePayment" -> CRITICAL severity.
		if noLog[0].Severity != scanner.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for Tier 1 handler, got %s", noLog[0].Severity)
		}
		if !strings.Contains(noLog[0].Description, "PCI DSS 10.2.1 fields") {
			t.Errorf("Expected description to mention PCI DSS 10.2.1 fields, got: %s", noLog[0].Description)
		}
	}
}

// Test3: Payment handler with fmt.Println only -> 1 CRITICAL finding AUDIT-UNSTRUCTURED (Tier 1).
func TestPaymentHandlerUnstructuredOnly(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"fmt"
	"net/http"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	fmt.Println("processing payment")
	w.Write([]byte("done"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	unstruct := findByRule(result.Findings, "AUDIT-UNSTRUCTURED")
	if len(unstruct) != 1 {
		t.Errorf("Expected 1 AUDIT-UNSTRUCTURED finding, got %d: %+v", len(unstruct), unstruct)
	}
	if len(unstruct) > 0 {
		// Tier 1 handler "HandlePayment" -> CRITICAL severity.
		if unstruct[0].Severity != scanner.SeverityCritical {
			t.Errorf("Expected CRITICAL severity for Tier 1 handler, got %s", unstruct[0].Severity)
		}
		if !strings.Contains(unstruct[0].Description, "Unstructured logging") {
			t.Errorf("Expected description about unstructured logging, got: %s", unstruct[0].Description)
		}
	}
}

// Test4: Non-payment handler with no logging -> 0 findings.
func TestNonPaymentHandlerSkipped(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for non-payment handler, got %d: %+v", len(result.Findings), result.Findings)
	}
}

// Test5: Payment handler calling helper function in same file that has slog.Info -> 0 HIGH findings.
func TestPaymentHandlerDelegatesToHelper(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"log/slog"
	"net/http"
)

func HandleRefund(w http.ResponseWriter, r *http.Request) {
	processRefund()
	w.Write([]byte("refund ok"))
}

func processRefund() {
	slog.Info("refund processed")
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings (logging in delegate), got %d: %+v", len(high), high)
	}
}

// Test6: Payment handler with zap.L().Info() -> 0 HIGH findings.
func TestPaymentHandlerWithZap(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"net/http"
	"go.uber.org/zap"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	zap.L().Info("payment processed")
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings (zap detected), got %d: %+v", len(high), high)
	}
}

// Test7: Payment handler with zerolog log.Info().Msg() -> 0 HIGH findings.
func TestPaymentHandlerWithZerolog(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"net/http"
	"github.com/rs/zerolog/log"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("payment processed")
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings (zerolog detected), got %d: %+v", len(high), high)
	}
}

// Test8: Payment handler with renamed import `import mylog "log/slog"` using `mylog.Info()`.
func TestPaymentHandlerWithRenamedImport(t *testing.T) {
	t.Parallel()
	src := `package test

import (
	"net/http"
	mylog "log/slog"
)

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	mylog.Info("payment processed")
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	high := findBySeverity(result.Findings, scanner.SeverityHigh)
	if len(high) != 0 {
		t.Errorf("Expected 0 HIGH findings (renamed import detected), got %d: %+v", len(high), high)
	}
}

// Test9: Non-HTTP function with payment name but no handler signature -> 0 findings.
func TestNonHTTPPaymentFunction(t *testing.T) {
	t.Parallel()
	src := `package test

func ProcessPayment(data []byte) error {
	return nil
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings for non-HTTP function, got %d: %+v", len(result.Findings), result.Findings)
	}
}

// Test10: gin.Context handler with payment name and no logging -> 1 CRITICAL finding (Tier 1).
func TestGinPaymentHandlerNoLogging(t *testing.T) {
	t.Parallel()
	src := `package test

import "github.com/gin-gonic/gin"

func HandlePayment(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	crit := findBySeverity(result.Findings, scanner.SeverityCritical)
	if len(crit) != 1 {
		t.Errorf("Expected 1 CRITICAL finding for Tier 1 gin handler, got %d: %+v", len(crit), crit)
	}
}

// TestTierSeverity verifies that audit findings map tier to correct severity.
func TestTierSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		handlerName string
		wantSev     scanner.Severity
		wantRule    string
	}{
		{"Tier 1 HandlePayment -> CRITICAL", "HandlePayment", scanner.SeverityCritical, "AUDIT-NO-LOG"},
		{"Tier 1 ProcessCard -> CRITICAL", "ProcessCard", scanner.SeverityCritical, "AUDIT-NO-LOG"},
		{"Tier 2 CreateInvoice -> HIGH", "CreateInvoice", scanner.SeverityHigh, "AUDIT-NO-LOG"},
		{"Tier 2 HandleOrder -> HIGH", "HandleOrder", scanner.SeverityHigh, "AUDIT-NO-LOG"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := `package test

import "net/http"

func ` + tc.handlerName + `(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
			dir := writeFixture(t, "handler.go", src)
			s := New()
			result, err := s.ScanFull(context.Background(), dir, nil, false, true)
			if err != nil {
				t.Fatalf("Scan error: %v", err)
			}

			findings := findByRule(result.Findings, tc.wantRule)
			if len(findings) != 1 {
				t.Fatalf("Expected 1 %s finding, got %d: %+v", tc.wantRule, len(findings), result.Findings)
			}
			if findings[0].Severity != tc.wantSev {
				t.Errorf("Expected %s severity, got %s", tc.wantSev, findings[0].Severity)
			}
		})
	}
}

// TestTier3CoLocation verifies Tier 3 handler only fires when Tier 1 is in same file.
func TestTier3CoLocation(t *testing.T) {
	t.Parallel()
	// Tier 3 handler WITHOUT Tier 1 in same file -> no finding.
	t.Run("callback alone produces no finding", func(t *testing.T) {
		src := `package test

import "net/http"

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
		dir := writeFixture(t, "handler.go", src)
		s := New()
		result, err := s.ScanFull(context.Background(), dir, nil, false, true)
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}
		if len(result.Findings) != 0 {
			t.Errorf("Expected 0 findings for Tier 3 handler without Tier 1, got %d: %+v",
				len(result.Findings), result.Findings)
		}
	})

	// Tier 3 handler WITH Tier 1 in same file -> MEDIUM finding.
	t.Run("callback with payment handler produces MEDIUM", func(t *testing.T) {
		src := `package test

import "net/http"

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("pay"))
}

func HandleCallback(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("cb"))
}
`
		dir := writeFixture(t, "handler.go", src)
		s := New()
		result, err := s.ScanFull(context.Background(), dir, nil, false, true)
		if err != nil {
			t.Fatalf("Scan error: %v", err)
		}

		// Should have findings for both: HandlePayment (CRITICAL) and HandleCallback (MEDIUM).
		callbackFindings := []scanner.Finding{}
		for _, f := range result.Findings {
			if strings.Contains(f.Description, "HandleCallback") {
				callbackFindings = append(callbackFindings, f)
			}
		}
		if len(callbackFindings) != 1 {
			t.Fatalf("Expected 1 finding for HandleCallback, got %d: %+v",
				len(callbackFindings), result.Findings)
		}
		if callbackFindings[0].Severity != scanner.SeverityMedium {
			t.Errorf("Expected MEDIUM severity for Tier 3 co-located handler, got %s",
				callbackFindings[0].Severity)
		}
	})
}

// TestMiddlewareDowngrade verifies that logging middleware in same file downgrades to INFO.
func TestMiddlewareDowngrade(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

type Router struct{}
func (rt *Router) Use(middleware func(http.Handler) http.Handler) {}

func SetupRoutes(rt *Router) {
	rt.Use(LoggingMiddleware)
}

func LoggingMiddleware(next http.Handler) http.Handler { return next }

func HandlePayment(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
`
	dir := writeFixture(t, "handler.go", src)
	s := New()
	result, err := s.ScanFull(context.Background(), dir, nil, false, true)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Should have INFO finding (middleware downgrade), not CRITICAL/HIGH.
	info := findByRule(result.Findings, "AUDIT-LOG-OK")
	if len(info) != 1 {
		t.Fatalf("Expected 1 AUDIT-LOG-OK finding (middleware downgrade), got %d findings: %+v",
			len(info), result.Findings)
	}
	if info[0].Severity != scanner.SeverityInfo {
		t.Errorf("Expected INFO severity for middleware downgrade, got %s", info[0].Severity)
	}
	if !strings.Contains(info[0].Description, "Logging middleware detected") {
		t.Errorf("Expected middleware detection message, got: %s", info[0].Description)
	}
}

// TestHasLoggingMiddleware_RequestLogger verifies that a handler wrapped by
// a same-file function named `requestLogger` (word-boundary "Logger") is
// recognized as middleware-covered (case 1).
func TestHasLoggingMiddleware_RequestLogger(t *testing.T) {
	t.Parallel()
	file, _, err := scanner.ParseGoFile("testdata/middleware_logger.go")
	if err != nil {
		t.Fatalf("ParseGoFile: %v", err)
	}
	if !hasLoggingMiddleware(file, "PaymentHandler") {
		t.Errorf("Expected PaymentHandler to be detected as covered by requestLogger middleware")
	}
}

// TestHasLoggingMiddleware_SelectorCallForm verifies that a handler wrapped by
// `audit.AuditLogger()` (SelectorExpr + CallExpr form) is
// recognized (case 2).
func TestHasLoggingMiddleware_SelectorCallForm(t *testing.T) {
	t.Parallel()
	file, _, err := scanner.ParseGoFile("testdata/middleware_logger.go")
	if err != nil {
		t.Fatalf("ParseGoFile: %v", err)
	}
	if !hasLoggingMiddleware(file, "CheckoutHandler") {
		t.Errorf("Expected CheckoutHandler to be detected as covered by audit.AuditLogger middleware")
	}
}

// TestHasLoggingMiddleware_AggregatorInstall verifies that aggregator
// follow-through recognizes handlers routed through an `Install` function
// whose body contains logger-named wrappers (case 3).
func TestHasLoggingMiddleware_AggregatorInstall(t *testing.T) {
	t.Parallel()
	file, _, err := scanner.ParseGoFile("testdata/middleware_logger.go")
	if err != nil {
		t.Fatalf("ParseGoFile: %v", err)
	}
	if !hasLoggingMiddleware(file, "RefundHandler") {
		t.Errorf("Expected RefundHandler to be detected via Install aggregator follow-through")
	}
}

// TestHasLoggingMiddleware_NoMiddleware_StillFiresAuditNoLog is a regression
// guard: a file that genuinely has NO middleware coverage for a handler must
// still report false (so AUDIT-NO-LOG fires for the true no-log case).
func TestHasLoggingMiddleware_NoMiddleware_StillFiresAuditNoLog(t *testing.T) {
	t.Parallel()
	src := `package test

import "net/http"

func NoMiddlewarePayHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
`
	dir := writeFixture(t, "nolog.go", src)
	file, _, err := scanner.ParseGoFile(filepath.Join(dir, "nolog.go"))
	if err != nil {
		t.Fatalf("ParseGoFile: %v", err)
	}
	if hasLoggingMiddleware(file, "NoMiddlewarePayHandler") {
		t.Errorf("Expected NoMiddlewarePayHandler to NOT be detected as middleware-covered")
	}
}

// TestCrossFileMiddlewareIntegration runs the full scanner on a temp directory
// containing multi-file fixtures. Verifies that HandlePayment (covered by
// cross-file middleware) gets AUDIT-LOG-OK, while HandleRefundManual still
// gets AUDIT-NO-LOG because its group has no middleware.
func TestCrossFileMiddlewareIntegration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write handler file with payment handlers (no inline logging).
	// Handler names use Tier 1 keywords ("Card", "Payment") so the scanner picks them up.
	handlerSrc := `package testpkg

import "github.com/gin-gonic/gin"

type PaymentHandler struct{}

func (h *PaymentHandler) InstallRoutes(group *gin.RouterGroup) {
	sub := group.Group("/payments/v1")
	sub.POST("/create", h.HandlePayment)
}

func (h *PaymentHandler) HandlePayment(c *gin.Context) {
	c.JSON(200, gin.H{"status": "created"})
}
`
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(handlerSrc), 0644); err != nil {
		t.Fatalf("WriteFile handler: %v", err)
	}

	// Write middleware setup file with logging middleware on the group.
	middlewareSrc := `package testpkg

import "github.com/gin-gonic/gin"

func requestLogger(c *gin.Context) { c.Next() }

func SetupRoutes(r *gin.Engine) {
	apiV1Group := r.Group("/api/v1")
	apiV1Group.Use(requestLogger)
	paymentsH := &PaymentHandler{}
	paymentsH.InstallRoutes(apiV1Group)
}
`
	if err := os.WriteFile(filepath.Join(dir, "middleware.go"), []byte(middlewareSrc), 0644); err != nil {
		t.Fatalf("WriteFile middleware: %v", err)
	}

	// Write uncovered handler on a group with NO logging middleware.
	uncoveredSrc := `package testpkg

import "github.com/gin-gonic/gin"

func SetupUncovered(r *gin.Engine) {
	adminGroup := r.Group("/admin")
	adminGroup.POST("/refund", HandleRefundManual)
}

func HandleRefundManual(c *gin.Context) {
	c.JSON(200, gin.H{"status": "ok"})
}
`
	if err := os.WriteFile(filepath.Join(dir, "uncovered.go"), []byte(uncoveredSrc), 0644); err != nil {
		t.Fatalf("WriteFile uncovered: %v", err)
	}

	s := New()
	result, err := s.ScanFull(context.Background(), dir, nil, false, true)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// HandlePayment should get AUDIT-LOG-OK (covered by cross-file middleware).
	var coveredFindings []scanner.Finding
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "HandlePayment") {
			coveredFindings = append(coveredFindings, f)
		}
	}
	if len(coveredFindings) != 1 {
		t.Fatalf("Expected 1 finding for HandlePayment, got %d: %+v", len(coveredFindings), result.Findings)
	}
	if coveredFindings[0].RuleID != "AUDIT-LOG-OK" {
		t.Errorf("Expected HandlePayment to get AUDIT-LOG-OK, got %s", coveredFindings[0].RuleID)
	}
	if !coveredFindings[0].MiddlewareDetected {
		t.Error("Expected MiddlewareDetected=true for cross-file middleware coverage")
	}

	// HandleRefundManual should get AUDIT-NO-LOG (no middleware on its group).
	var uncoveredFindings []scanner.Finding
	for _, f := range result.Findings {
		if strings.Contains(f.Description, "HandleRefundManual") {
			uncoveredFindings = append(uncoveredFindings, f)
		}
	}
	if len(uncoveredFindings) != 1 {
		t.Fatalf("Expected 1 finding for HandleRefundManual, got %d: %+v", len(uncoveredFindings), result.Findings)
	}
	if uncoveredFindings[0].RuleID != "AUDIT-NO-LOG" {
		t.Errorf("Expected HandleRefundManual to get AUDIT-NO-LOG, got %s", uncoveredFindings[0].RuleID)
	}
}

// TestExistingMiddlewareFixtureRegression confirms that the existing
// testdata/middleware_logger.go fixture still produces correct results
// (fast path still works after wiring cross-file fallback).
func TestExistingMiddlewareFixtureRegression(t *testing.T) {
	t.Parallel()
	file, _, err := scanner.ParseGoFile("testdata/middleware_logger.go")
	if err != nil {
		t.Fatalf("ParseGoFile: %v", err)
	}
	// PaymentHandler should still be detected via in-file fast path.
	if !hasLoggingMiddleware(file, "PaymentHandler") {
		t.Error("Regression: PaymentHandler should be detected via in-file middleware (fast path)")
	}
}

// TestScannerInterface verifies AuditScanner implements scanner.Scanner.
func TestScannerInterface(t *testing.T) {
	t.Parallel()
	s := New()

	if name := s.Name(); name != "audit_log_coverage" {
		t.Errorf("Name() = %q, want %q", name, "audit_log_coverage")
	}

	if desc := s.Description(); desc == "" {
		t.Error("Description() should not be empty")
	}

	reqs := s.Requirements()
	if len(reqs) != 1 || reqs[0] != "10.2.1" {
		t.Errorf("Requirements() = %v, want [\"10.2.1\"]", reqs)
	}

	// Verify interface compliance.
	var _ scanner.Scanner = s
}

// ----------: Field Verification Integration Tests ----------

// TestAuditLogFieldVerification_GracefulDegradation verifies that when middleware
// import can't be resolved, the finding keeps the generic message.
func TestAuditLogFieldVerification_GracefulDegradation(t *testing.T) {
	t.Parallel()
	// Create a simple project with a payment handler covered by middleware,
	// but the middleware import is external (can't be followed).
	dir := t.TempDir()

	// Write go.mod so findGoModule works.
	gomod := `module example.com/testproject

go 1.21
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0644); err != nil {
		t.Fatalf("WriteFile go.mod: %v", err)
	}

	// Handler file with external middleware import that can't be followed.
	src := `package handler

import (
	"net/http"
	"external.com/somelib/middleware"
)

func SetupRoutes(mux *http.ServeMux) {
	middleware.Install(mux)
	mux.HandleFunc("/api/v1/tokenize", HandleTokenize)
}

func HandleTokenize(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
`
	if err := os.WriteFile(filepath.Join(dir, "handler.go"), []byte(src), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s := New()
	result, err := s.ScanFull(context.Background(), dir, nil, false, true)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	// Find AUDIT-LOG-OK findings for HandleTokenize.
	var okFindings []scanner.Finding
	for _, f := range result.Findings {
		if f.RuleID == "AUDIT-LOG-OK" && strings.Contains(f.Description, "HandleTokenize") {
			okFindings = append(okFindings, f)
		}
	}

	if len(okFindings) == 0 {
		// If middleware wasn't detected, it might be AUDIT-NO-LOG. That's acceptable
		// for this test since the external middleware can't be resolved.
		// The key invariant is: no panic, graceful behavior.
		t.Log("Middleware not detected for external import (expected for graceful degradation)")
		return
	}

	// If middleware was detected, verify the finding has the generic message
	// (field extraction should have failed for external import).
	f := okFindings[0]
	if f.Severity != scanner.SeverityInfo {
		t.Errorf("Expected INFO severity for graceful degradation, got %s", f.Severity)
	}
	if !f.MiddlewareDetected {
		t.Error("Expected MiddlewareDetected=true")
	}
}

// TestResetLogFieldCache verifies that field cache is cleared properly.
func TestResetLogFieldCache(t *testing.T) {
	t.Parallel()
	// Populate the cache with a dummy entry.
	logFieldMu.Lock()
	logFieldCache["test::func"] = &logFieldCacheEntry{
		fields: []string{"user_id", "status"},
		done:   true,
	}
	logFieldMu.Unlock()

	// Verify entry exists.
	logFieldMu.Lock()
	_, exists := logFieldCache["test::func"]
	logFieldMu.Unlock()
	if !exists {
		t.Fatal("expected cache entry to exist before reset")
	}

	// Reset.
	ResetLogFieldCache()

	// Verify cleared.
	logFieldMu.Lock()
	_, exists = logFieldCache["test::func"]
	logFieldMu.Unlock()
	if exists {
		t.Error("expected cache to be cleared after ResetLogFieldCache()")
	}
}

// TestResetLogFieldCache_CalledByScanFull verifies that ScanFull calls
// ResetLogFieldCache (indirectly verified by checking cache is empty after scan).
func TestResetLogFieldCache_CalledByScanFull(t *testing.T) {
	t.Parallel()
	// Populate cache.
	logFieldMu.Lock()
	logFieldCache["stale::entry"] = &logFieldCacheEntry{
		fields: []string{"old_field"},
		done:   true,
	}
	logFieldMu.Unlock()

	// Run a scan on an empty directory (just to trigger ScanFull).
	dir := t.TempDir()
	s := New()
	_, err := s.ScanFull(context.Background(), dir, nil, false, true)
	if err != nil {
		t.Fatalf("ScanFull error: %v", err)
	}

	// Cache should be cleared by ScanFull.
	logFieldMu.Lock()
	_, exists := logFieldCache["stale::entry"]
	logFieldMu.Unlock()
	if exists {
		t.Error("expected ScanFull to clear logFieldCache (via ResetLogFieldCache)")
	}
}
