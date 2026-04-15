package taint

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// absFixture returns the absolute path to a testdata fixture directory so
// packages.Load can resolve it regardless of the test's CWD.
func absFixture(t testing.TB, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("abs fixture path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(p, "go.mod")); err != nil {
		t.Fatalf("fixture missing go.mod: %v", err)
	}
	return p
}

// resetAround wires taint.Reset into both setup and teardown so any shared
// engine cache state between tests is cleaned under -race.
func resetAround(t testing.TB) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)
}

func TestGetOrInit_HealthyProject(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "stored_model")
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Fatalf("expected engine for healthy fixture, got nil")
	}
	if !engine.loadOK {
		t.Fatalf("expected loadOK=true for healthy fixture")
	}
	if len(engine.pkgs) == 0 {
		t.Fatalf("expected at least one loaded package")
	}
	// Cache stores the engine keyed by absolute root.
	engineMu.Lock()
	_, cached := engineCache[root]
	engineMu.Unlock()
	if !cached {
		t.Fatalf("expected engineCache to hold entry for %q", root)
	}
}

func TestGetOrInit_NoGoBinary(t *testing.T) {
	resetAround(t)
	// t.Setenv restores the original PATH on cleanup.
	t.Setenv("PATH", "")
	root := absFixture(t, "stored_model")
	if engine := GetOrInit(context.Background(), root); engine != nil {
		t.Fatalf("expected nil engine when go binary missing")
	}
	// Second call should hit the cached-failed branch without panic.
	if engine := GetOrInit(context.Background(), root); engine != nil {
		t.Fatalf("expected nil on repeat call with cached-failed engine")
	}
}

func TestGetOrInit_Timeout(t *testing.T) {
	resetAround(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	root := absFixture(t, "stored_model")
	if engine := GetOrInit(ctx, root); engine != nil {
		t.Fatalf("expected nil engine when load context already expired")
	}
}

func TestGetOrInit_TypecheckErrors(t *testing.T) {
	resetAround(t)
	// Build a throwaway broken module in a tempdir so the main testdata is
	// not polluted.
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module example.com/broken\n\ngo 1.25\n")
	mustWrite(t, filepath.Join(dir, "main.go"), `package broken

func bar() {
	undefined_symbol(nonexistent_var)
}
`)
	if engine := GetOrInit(context.Background(), dir); engine != nil {
		t.Fatalf("expected nil engine for module with typecheck errors")
	}
}

func TestGetOrInit_Cached(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "stored_model")
	e1 := GetOrInit(context.Background(), root)
	if e1 == nil {
		t.Skip("taint engine unavailable (go binary missing?) — cannot exercise cache path")
	}
	e2 := GetOrInit(context.Background(), root)
	if e1 != e2 {
		t.Fatalf("expected identical cached engine pointer, got %p vs %p", e1, e2)
	}
}

func TestReset(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "stored_model")
	e1 := GetOrInit(context.Background(), root)
	if e1 == nil {
		t.Skip("taint engine unavailable — cannot exercise Reset")
	}
	Reset()
	e2 := GetOrInit(context.Background(), root)
	if e2 == nil {
		t.Fatalf("expected rebuild after Reset, got nil")
	}
	if e1 == e2 {
		t.Fatalf("expected different engine pointer after Reset")
	}
}

func TestDeferredSinks_Empty(t *testing.T) {
	resetAround(t)
	root := absFixture(t, "stored_model")
	engine := GetOrInit(context.Background(), root)
	if engine == nil {
		t.Skip("taint engine unavailable")
	}
	src := Source{Package: "example.com/storedmodel", TypeName: "Card", Field: "Number"}
	for _, kind := range []SinkKind{SinkHTTPResponse, SinkLoggerCall, SinkCryptoCall} {
		got := engine.FlowsTo(src, SinkPattern{Kind: kind})
		if got {
			t.Errorf("expected FlowsTo=false for deferred sink kind %v, got true", kind)
		}
		// resolveSinks should report zero targets for deferred kinds.
		targets := engine.resolveSinks(SinkPattern{Kind: kind})
		if len(targets) != 0 {
			t.Errorf("expected 0 sink targets for deferred kind %v, got %d", kind, len(targets))
		}
	}
}

func BenchmarkLoadTaintEngine(b *testing.B) {
	b.ReportAllocs()
	root := absFixture(b, "stored_model")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Reset()
		engine := GetOrInit(context.Background(), root)
		if engine == nil {
			b.Fatalf("engine load failed")
		}
	}
}

func mustWrite(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
