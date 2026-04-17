package authscanner

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func getFnBody(decl any) *ast.BlockStmt {
	if fn, ok := decl.(*ast.FuncDecl); ok {
		return fn.Body
	}
	return nil
}

func TestBrandPathRE(t *testing.T) {
	tt := []struct {
		name  string
		path  string
		match bool
	}{
		{"stripe webhooks", "/webhooks/stripe", true},
		{"adyen callbacks plural", "/callbacks/adyen", true},
		{"paypal ipn nested", "/webhooks/paypal/ipn", true},
		{"visa notifications", "/notifications/visa-update", true},
		{"google-pay hooks", "/hooks/google-pay", true},
		{"mastercard callback", "/callback/mastercard", true},
		{"checkout but not webhook prefix", "/checkout/done", false},
		{"plain webhooks no brand", "/webhooks/foo", false},
		{"plain api path", "/api/internal/sync", false},
		{"visa internal not webhook prefix", "/internal/visa/process", false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := brandPathRE.MatchString(tc.path)
			if got != tc.match {
				t.Errorf("brandPathRE.MatchString(%q) = %v, want %v", tc.path, got, tc.match)
			}
		})
	}
}

func TestFirstBodyParserPos(t *testing.T) {
	tt := []struct {
		name       string
		body       string
		wantHasPos bool
		wantTagSub string
	}{
		{"json.NewDecoder Decode", `var p map[string]any; json.NewDecoder(r.Body).Decode(&p)`, true, "Decode"},
		{"json.Unmarshal", `var p map[string]any; _ = json.Unmarshal(b, &p)`, true, "json.Unmarshal"},
		{"c.ShouldBindJSON", `var p map[string]any; c.ShouldBindJSON(&p)`, true, "ShouldBindJSON"},
		{"io.ReadAll only NOT parser", `body, _ := io.ReadAll(r.Body); _ = body`, false, ""},
		{"GetRawData only NOT parser", `body, _ := c.GetRawData(); _ = body`, false, ""},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc h() {\n" + tc.body + "\n}\n"
			file, _ := parseSrc(t, src)
			body := getFnBody(file.Decls[0])
			pos, tag := firstBodyParserPos(body)
			hasPos := pos != token.NoPos
			if hasPos != tc.wantHasPos {
				t.Fatalf("hasPos=%v want %v (tag=%q)", hasPos, tc.wantHasPos, tag)
			}
			if tc.wantTagSub != "" && !strings.Contains(tag, tc.wantTagSub) {
				t.Errorf("tag=%q does not contain %q", tag, tc.wantTagSub)
			}
		})
	}
}

func TestSignatureVerifiedBeforeParser(t *testing.T) {
	tt := []struct {
		name string
		body string
		want bool
	}{
		{"hmac.Equal before Decode", `body, _ := io.ReadAll(r.Body); hmac.Equal([]byte("a"), []byte("b")); var p map[string]any; json.Unmarshal(body, &p)`, true},
		{"hmac.Equal AFTER Decode", `var p map[string]any; json.NewDecoder(r.Body).Decode(&p); hmac.Equal([]byte("a"), []byte("b"))`, false},
		{"no sig at all", `var p map[string]any; json.NewDecoder(r.Body).Decode(&p)`, false},
		{"webhook.ConstructEvent before parser", `body, _ := io.ReadAll(r.Body); webhook.ConstructEvent(body, "sig", "secret"); var p map[string]any; json.Unmarshal(body, &p)`, true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc h() {\n" + tc.body + "\n}\n"
			file, _ := parseSrc(t, src)
			body := getFnBody(file.Decls[0])
			parserPos, _ := firstBodyParserPos(body)
			if parserPos == token.NoPos {
				t.Fatal("test setup: parser pos must be set")
			}
			pkgFuncs := collectFileFuncs(file)
			got, _ := signatureVerifiedBeforeParser(body, parserPos, pkgFuncs)
			if got != tc.want {
				t.Errorf("signatureVerifiedBeforeParser = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVerifySigRecursionDepth2Fails(t *testing.T) {
	src := `package p
func h() {
	body, _ := io.ReadAll(r.Body)
	_ = body
	if !verifyOuter(body) { return }
	var p map[string]any
	_ = json.Unmarshal(body, &p)
}
func verifyOuter(body []byte) bool {
	return verifyInner(body)
}
func verifyInner(body []byte) bool {
	return hmac.Equal(body, body)
}
`
	file, _ := parseSrc(t, src)
	body := getFnBody(file.Decls[0])
	parserPos, _ := firstBodyParserPos(body)
	pkgFuncs := collectFileFuncs(file)
	got, _ := signatureVerifiedBeforeParser(body, parserPos, pkgFuncs)
	if got {
		t.Errorf("expected depth-2 recursion to FAIL (verifyOuter -> verifyInner -> hmac.Equal), got verified=true")
	}
}

func TestVerifySigRecursionDepth1Passes(t *testing.T) {
	src := `package p
func h() {
	body, _ := io.ReadAll(r.Body)
	_ = body
	if !verifyHelper(body) { return }
	var p map[string]any
	_ = json.Unmarshal(body, &p)
}
func verifyHelper(body []byte) bool {
	return hmac.Equal(body, body)
}
`
	file, _ := parseSrc(t, src)
	body := getFnBody(file.Decls[0])
	parserPos, _ := firstBodyParserPos(body)
	pkgFuncs := collectFileFuncs(file)
	got, _ := signatureVerifiedBeforeParser(body, parserPos, pkgFuncs)
	if !got {
		t.Errorf("expected depth-1 recursion to PASS (verifyHelper -> hmac.Equal directly)")
	}
}

func TestVerifySigCycleGuard(t *testing.T) {
	src := `package p
func h() {
	body, _ := io.ReadAll(r.Body)
	_ = body
	if !verifyA(body) { return }
	var p map[string]any
	_ = json.Unmarshal(body, &p)
}
func verifyA(body []byte) bool { return verifyB(body) }
func verifyB(body []byte) bool { return verifyA(body) }
`
	file, _ := parseSrc(t, src)
	body := getFnBody(file.Decls[0])
	parserPos, _ := firstBodyParserPos(body)
	pkgFuncs := collectFileFuncs(file)
	done := make(chan bool, 1)
	go func() {
		signatureVerifiedBeforeParser(body, parserPos, pkgFuncs)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("cycle guard failed: signatureVerifiedBeforeParser hung on cyclic helpers")
	}
}

func TestWebhookSignatureScanIntegrationStripeAntiPattern(t *testing.T) {
	src := `package webhook
import (
	"encoding/json"
	"net/http"
)
func InstallStripeRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/stripe", HandleStripeWebhook)
}
func HandleStripeWebhook(w http.ResponseWriter, r *http.Request) {
	var event map[string]any
	_ = json.NewDecoder(r.Body).Decode(&event)
}
`
	file, fset := parseSrc(t, src)
	out := WebhookSignatureScan(file, fset, "test.go", ".")
	hit := false
	for _, f := range out {
		if f.RuleID != RuleAuthWebhookNoSignature {
			continue
		}
		if f.Severity != scanner.SeverityCritical {
			t.Errorf("severity=%v, want CRITICAL (brand=stripe)", f.Severity)
		}
		hasCHD := false
		for _, r := range f.RelatedRequirements {
			if r == "4.2.1" {
				hasCHD = true
			}
		}
		if !hasCHD {
			t.Errorf("RelatedRequirements missing 4.2.1, got %v", f.RelatedRequirements)
		}
		hit = true
	}
	if !hit {
		t.Errorf("expected AUTH-WEBHOOK-NO-SIGNATURE on Stripe canonical anti-pattern")
	}
}

func TestWebhookSignatureScanIntegrationVerifiedConstructEvent(t *testing.T) {
	src := `package webhook
import (
	"encoding/json"
	"io"
	"net/http"
)
type c struct{}
func (c) ConstructEvent(body []byte, sig, secret string) (any, error) { return nil, nil }
var webhook = c{}
var _ = io.ReadAll
func InstallVerifiedRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/webhooks/stripe", HandleVerifiedStripe)
}
func HandleVerifiedStripe(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_, _ = webhook.ConstructEvent(body, "sig", "secret")
	var event map[string]any
	_ = json.Unmarshal(body, &event)
}
`
	file, fset := parseSrc(t, src)
	out := WebhookSignatureScan(file, fset, "test.go", ".")
	hit := false
	for _, f := range out {
		if f.RuleID == RuleAuthWebhookVerified {
			hit = true
			if f.Severity != scanner.SeverityInfo {
				t.Errorf("verified must be INFO, got %v", f.Severity)
			}
			if !strings.HasPrefix(f.TriageHint, webhookVerifiedTag) {
				t.Errorf("TriageHint=%q must start with %q", f.TriageHint, webhookVerifiedTag)
			}
		}
		if f.RuleID == RuleAuthWebhookNoSignature {
			t.Errorf("verified handler should NOT emit AUTH-WEBHOOK-NO-SIGNATURE")
		}
	}
	if !hit {
		t.Errorf("expected AUTH-WEBHOOK-VERIFIED on ConstructEvent flow")
	}
}

func TestWebhookSignatureScanGenericPathHigh(t *testing.T) {
	src := `package webhook
import (
	"encoding/json"
	"net/http"
)
func InstallGenericRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/hooks/payment", ProcessPaymentHookCallback)
}
func ProcessPaymentHookCallback(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	_ = json.Unmarshal(nil, &payload)
}
`
	file, fset := parseSrc(t, src)
	out := WebhookSignatureScan(file, fset, "test.go", ".")
	hit := false
	for _, f := range out {
		if f.RuleID != RuleAuthWebhookNoSignature {
			continue
		}
		if f.Severity != scanner.SeverityHigh {
			t.Errorf("severity=%v, want HIGH (generic path)", f.Severity)
		}
		if len(f.RelatedRequirements) > 0 {
			t.Errorf("generic path should have empty RelatedRequirements, got %v", f.RelatedRequirements)
		}
		hit = true
	}
	if !hit {
		t.Errorf("expected AUTH-WEBHOOK-NO-SIGNATURE HIGH on /hooks/payment generic path")
	}
}
