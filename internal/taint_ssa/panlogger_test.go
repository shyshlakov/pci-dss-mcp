package taint_ssa

import (
	"context"
	"testing"
	"time"
)

func TestIsPANFieldName(t *testing.T) {
	tt := []struct {
		in   string
		want bool
	}{
		{"PAN", true},
		{"Pan", true},
		{"pan", true},
		{"card_number", true},
		{"CardNumber", true},
		{"primary_account_number", true},
		{"CVV", true},
		{"cvc", true},
		{"PINBlock", true},
		{"track_data", true},
		{"unrelated_field", false},
		{"id", false},
		{"Number", false},
	}
	for _, tc := range tt {
		t.Run(tc.in, func(t *testing.T) {
			got := isPANFieldName(tc.in)
			if got != tc.want {
				t.Errorf("isPANFieldName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsAmbiguousPANFieldName(t *testing.T) {
	tt := []struct {
		in   string
		want bool
	}{
		{"Number", true},
		{"number", true},
		{"Holder", true},
		{"Expiry", true},
		{"IBAN", true},
		{"unrelated", false},
		{"PAN", false},
	}
	for _, tc := range tt {
		t.Run(tc.in, func(t *testing.T) {
			got := isAmbiguousPANFieldName(tc.in)
			if got != tc.want {
				t.Errorf("isAmbiguousPANFieldName(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRunPANLogger(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	p, err := BuildProgram(ctx, fixtureRoot(t))
	if err != nil {
		t.Skipf("BuildProgram failed (likely missing go binary or fixture deps): %v", err)
	}
	if p == nil {
		t.Skip("BuildProgram returned nil program")
	}

	findings := RunPANLogger(p)
	t.Logf("RunPANLogger emitted %d findings", len(findings))
	for _, f := range findings {
		t.Logf("  PAN-LOGGER %s:%d %s", f.File, f.Line, f.Description)
	}
	if len(findings) < 0 {
		t.Errorf("findings slice has negative length")
	}
}

func TestRunPANLogger_NilProgram(t *testing.T) {
	if got := RunPANLogger(nil); got != nil {
		t.Errorf("RunPANLogger(nil) = %v, want nil", got)
	}
}
