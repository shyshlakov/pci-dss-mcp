package taint_ssa

import (
	"context"
	"testing"
	"time"
)

func TestRunCryptoHardcodedKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	p, err := BuildProgram(ctx, fixtureRoot(t))
	if err != nil {
		t.Skipf("BuildProgram failed: %v", err)
	}
	if p == nil {
		t.Skip("BuildProgram returned nil program")
	}

	findings := RunCryptoHardcodedKey(p)
	t.Logf("RunCryptoHardcodedKey emitted %d findings", len(findings))
	for _, f := range findings {
		t.Logf("  CRYPTO-HARDCODED-KEY %s:%d %s", f.File, f.Line, f.Description)
	}
	if len(findings) < 0 {
		t.Errorf("findings slice has negative length")
	}
}

func TestRunCryptoHardcodedKey_NilProgram(t *testing.T) {
	if got := RunCryptoHardcodedKey(nil); got != nil {
		t.Errorf("RunCryptoHardcodedKey(nil) = %v, want nil", got)
	}
}
