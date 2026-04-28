package httpinputscanner

import (
	"context"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestScannerIdentity(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "Name returns http_input_taint",
			run: func(t *testing.T) {
				s := New()
				if got := s.Name(); got != "http_input_taint" {
					t.Fatalf("Name() = %q, want http_input_taint", got)
				}
			},
		},
		{
			name: "Description is non-empty",
			run: func(t *testing.T) {
				s := New()
				if s.Description() == "" {
					t.Fatal("Description() empty")
				}
			},
		},
		{
			name: "Requirements include 10.2.1 6.2.4 3.3.1 3.5.1",
			run: func(t *testing.T) {
				s := New()
				want := map[string]bool{"10.2.1": false, "6.2.4": false, "3.3.1": false, "3.5.1": false}
				for _, r := range s.Requirements() {
					want[r] = true
				}
				for k, v := range want {
					if !v {
						t.Fatalf("Requirements() missing %q", k)
					}
				}
			},
		},
		{
			name: "Scan returns INFO HTTP-INPUT-TAINT-OFF when taint disabled",
			run: func(t *testing.T) {
				s := New()
				result, err := s.Scan(context.Background(), t.TempDir())
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if len(result.Findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(result.Findings))
				}
				f := result.Findings[0]
				if f.RuleID != "HTTP-INPUT-TAINT-OFF" {
					t.Fatalf("RuleID = %q, want HTTP-INPUT-TAINT-OFF", f.RuleID)
				}
				if f.Severity != scanner.SeverityInfo {
					t.Fatalf("Severity = %q, want INFO", f.Severity)
				}
			},
		},
		{
			name: "satisfies scanner.Scanner interface",
			run: func(t *testing.T) {
				var _ scanner.Scanner = New()
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}

func TestPanKeywordSeverity(t *testing.T) {
	tt := []struct {
		name           string
		ctx            UserInputContext
		wantSeverity   scanner.Severity
		wantShouldEmit bool
	}{
		{name: "pan promotes to HIGH", ctx: UserInputContext{Identifier: "pan"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "card promotes to HIGH", ctx: UserInputContext{Identifier: "card_number"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "cvv promotes to HIGH", ctx: UserInputContext{Identifier: "cvv"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "iban promotes to HIGH", ctx: UserInputContext{Identifier: "IBAN"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "bin stays MEDIUM", ctx: UserInputContext{Identifier: "bin"}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
		{name: "user stays MEDIUM", ctx: UserInputContext{Identifier: "user"}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
		{name: "empty stays MEDIUM", ctx: UserInputContext{Identifier: ""}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			gotSev, gotEmit := computeSeverity(tc.ctx)
			if gotEmit != tc.wantShouldEmit {
				t.Fatalf("computeSeverity(%q) shouldEmit = %v, want %v", tc.ctx.Identifier, gotEmit, tc.wantShouldEmit)
			}
			if gotEmit && gotSev != tc.wantSeverity {
				t.Fatalf("computeSeverity(%q) = %q, want %q", tc.ctx.Identifier, gotSev, tc.wantSeverity)
			}
		})
	}
}

func TestTriageHintFor(t *testing.T) {
	tt := []struct {
		ruleID string
		want   string
	}{
		{ruleID: "HTTP-INPUT-LOG", want: "http-input-leak"},
		{ruleID: "HTTP-INPUT-ERROR", want: "framework-input-error"},
		{ruleID: "HTTP-INPUT-PANIC", want: "recovery-leak"},
		{ruleID: "OTHER", want: ""},
	}
	for _, tc := range tt {
		t.Run(tc.ruleID, func(t *testing.T) {
			if got := triageHintFor(tc.ruleID); got != tc.want {
				t.Fatalf("triageHintFor(%q) = %q, want %q", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestSafeIdentifierFiltering(t *testing.T) {
	tt := []struct {
		name string
		id   string
		want bool
	}{
		{name: "X-Request-ID is safe", id: "X-Request-ID", want: true},
		{name: "user-agent lowercase is safe", id: "user-agent", want: true},
		{name: "X-Trace-Id is safe", id: "X-Trace-Id", want: true},
		{name: "Authorization is unsafe", id: "Authorization", want: false},
		{name: "token is unsafe", id: "token", want: false},
		{name: "empty is unsafe", id: "", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSafeIdentifier(tc.id); got != tc.want {
				t.Fatalf("isSafeIdentifier(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}
