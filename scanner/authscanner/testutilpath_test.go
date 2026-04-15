package authscanner

import (
	"strings"
	"testing"
)

func TestIsTestutilPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "internal testutil postgres", path: "internal/testutil/postgres/postgres.go", want: true},
		{name: "internal testutils postgres", path: "internal/testutils/postgres/postgres.go", want: true},
		{name: "pkg test helpers", path: "pkg/test/helpers.go", want: true},
		{name: "clean testutil fixture", path: "clean/testutil/db_fixture.go", want: true},
		{name: "internal payment admin", path: "internal/payment/hardcoded_admin.go", want: false},
		{name: "internal auth process", path: "internal/auth/process.go", want: false},
		{name: "cmd server main", path: "cmd/server/main.go", want: false},
		{name: "empty", path: "", want: false},
		{name: "internal test data seed", path: "internal/test/data/seed.go", want: true},
		{name: "contest not a match", path: "contest/internal/password.go", want: false},
		{name: "testdata root not matched", path: "testdata/vulnerable-payment-service/internal/auth/process.go", want: false},
		{name: "upper case segment", path: "TESTUTIL/HELPERS.GO", want: true},
		{name: "testutil underscore suffix", path: "internal/testutil_helpers/password.go", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTestutilPath(tt.path); got != tt.want {
				t.Errorf("isTestutilPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestTestutilTriageHint(t *testing.T) {
	got := testutilTriageHint()
	if !strings.HasPrefix(got, "downgrade:"+downgradeTagTestutil+" | ") {
		t.Errorf("testutilTriageHint() = %q, want prefix %q", got, "downgrade:"+downgradeTagTestutil+" | ")
	}
	if !strings.Contains(got, downgradeReasonTestutil) {
		t.Errorf("testutilTriageHint() = %q missing reason %q", got, downgradeReasonTestutil)
	}
}
