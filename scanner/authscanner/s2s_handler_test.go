package authscanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func parseSrc(t *testing.T, src string) (*ast.File, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return file, fset
}

func TestHandlerNameRegex(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name  string
		match bool
	}{
		{"MastercardWebhook", true},
		{"OnPaymentEvent", true},
		{"HandleStripeCallback", true},
		{"ProcessNotification", true},
		{"EventHandler", true},
		{"PaymentNotificationHandler", true},
		{"WebhookHandlerImpl", false},
		{"LoginUser", false},
		{"GetCardDetails", false},
		{"Authenticate", false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := handlerNameRE.MatchString(tc.name)
			if got != tc.match {
				t.Errorf("handlerNameRE.MatchString(%q) = %v, want %v", tc.name, got, tc.match)
			}
		})
	}
}

func TestS2SClassifierThreshold(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name   string
		strong int
		medium int
		weak   int
		want   bool
	}{
		{"T1 alone", 1, 0, 0, true},
		{"T2 medium consensus", 0, 2, 1, true},
		{"T2 only no T3", 0, 2, 0, false},
		{"single medium with T3", 0, 1, 1, false},
		{"weak only", 0, 0, 3, false},
		{"strong overrides everything", 1, 0, 0, true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			sc := signalCounts{Strong: tc.strong, Medium: tc.medium, Weak: tc.weak}
			if got := sc.isS2S(); got != tc.want {
				t.Errorf("isS2S() with strong=%d medium=%d weak=%d = %v, want %v", tc.strong, tc.medium, tc.weak, got, tc.want)
			}
		})
	}
}

func TestS2SClassifierNegativeSignal(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		body string
		kill bool
	}{
		{
			name: "gin-contrib session.Save",
			body: `session := foo(); session.Save()`,
			kill: true,
		},
		{
			name: "gin c.SetCookie 7-arg",
			body: `c.SetCookie("name", "value", 3600, "/", "domain", true, true)`,
			kill: true,
		},
		{
			name: "stdlib http.SetCookie 2-arg",
			body: `http.SetCookie(w, nil)`,
			kill: true,
		},
		{
			name: "raw w.Header().Set Set-Cookie",
			body: `w.Header().Set("Set-Cookie", "session_id=...")`,
			kill: true,
		},
		{
			name: "control no kill",
			body: `json.Unmarshal([]byte("{}"), nil)`,
			kill: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\nfunc h() {\n" + tc.body + "\n}\n"
			file, _ := parseSrc(t, src)
			fn := file.Decls[0].(*ast.FuncDecl)
			var sc signalCounts
			walkBodyForSignals(fn.Body, &sc)
			if sc.HasNegativeSignal != tc.kill {
				t.Errorf("HasNegativeSignal=%v, want %v", sc.HasNegativeSignal, tc.kill)
			}
		})
	}
}

func TestS2SDowngradeTag(t *testing.T) {
	t.Parallel()
	src := `package p

import (
	"crypto/hmac"
)

func ProcessStripeWebhook(body []byte, sig []byte, secret []byte) {
	hmac.Equal(sig, secret)
}
`
	file, fset := parseSrc(t, src)
	findings := []scanner.Finding{{
		RuleID:        "AUTH-MISSING-MFA",
		Severity:      scanner.SeverityHigh,
		RequirementID: "8.4.2",
		FilePath:      "test.go",
		Line:          fset.Position(file.Decls[1].Pos()).Line,
	}}
	out := ApplyS2SDowngrade(findings, file, fset, "test.go")
	if out[0].Severity != scanner.SeverityInfo {
		t.Errorf("Severity=%v want INFO", out[0].Severity)
	}
	if !strings.HasPrefix(out[0].TriageHint, "downgrade:s2s_handler") {
		t.Errorf("TriageHint=%q does not start with downgrade:s2s_handler", out[0].TriageHint)
	}
	hasMachine := false
	hasToken := false
	for _, r := range out[0].RelatedRequirements {
		if r == "8.6.1" {
			hasMachine = true
		}
		if r == "8.6.2" {
			hasToken = true
		}
	}
	if !hasMachine || !hasToken {
		t.Errorf("RelatedRequirements=%v missing 8.6.1 or 8.6.2", out[0].RelatedRequirements)
	}
	if out[0].RequirementID != "8.4.2" {
		t.Errorf("RequirementID=%q changed unexpectedly (want 8.4.2 unchanged)", out[0].RequirementID)
	}
}

func TestApplyS2SDowngradeNoOpOnOtherRules(t *testing.T) {
	t.Parallel()
	src := `package p
func H() {}`
	file, fset := parseSrc(t, src)
	findings := []scanner.Finding{
		{RuleID: "AUTH-HARDCODED-PWD", Severity: scanner.SeverityHigh, Line: 2},
		{RuleID: "AUDIT-NO-LOG", Severity: scanner.SeverityHigh, Line: 2},
	}
	out := ApplyS2SDowngrade(findings, file, fset, "test.go")
	for _, f := range out {
		if f.Severity != scanner.SeverityHigh {
			t.Errorf("rule %s severity changed: %v", f.RuleID, f.Severity)
		}
	}
}
