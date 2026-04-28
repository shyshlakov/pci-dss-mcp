package taint_ssa

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func fixtureRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "testdata", "vulnerable-payment-service")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	return abs
}

func TestBuildProgram(t *testing.T) {
	tt := []struct {
		name     string
		ctx      func() (context.Context, context.CancelFunc)
		root     func(t *testing.T) string
		wantErr  bool
		assertOK func(t *testing.T, p *Program)
	}{
		{
			name: "valid fixture root",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 90*time.Second)
			},
			root:    fixtureRoot,
			wantErr: false,
			assertOK: func(t *testing.T, p *Program) {
				if p == nil {
					t.Fatal("Program is nil")
				}
				if p.Prog == nil {
					t.Fatal("p.Prog is nil")
				}
				if len(p.Pkgs) == 0 {
					t.Fatal("p.Pkgs is empty")
				}
				fns := p.Functions()
				if len(fns) == 0 {
					t.Fatal("Functions returned empty slice")
				}
			},
		},
		{
			name: "empty root errors",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Second)
			},
			root:    func(*testing.T) string { return "" },
			wantErr: true,
		},
		{
			name: "nonexistent root errors",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 10*time.Second)
			},
			root:    func(*testing.T) string { return "/nonexistent/path/that/does/not/exist" },
			wantErr: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := tc.ctx()
			defer cancel()
			root := tc.root(t)
			p, err := BuildProgram(ctx, root)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (program=%v)", p != nil)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.assertOK != nil {
				tc.assertOK(t, p)
			}
		})
	}
}

func TestProgramPackageByPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	p, err := BuildProgram(ctx, fixtureRoot(t))
	if err != nil {
		t.Skipf("BuildProgram failed (likely missing go binary or fixture deps): %v", err)
	}
	if p == nil {
		t.Skip("BuildProgram returned nil program")
	}
	if pkg := p.PackageByPath("nonexistent.example/foo"); pkg != nil {
		t.Errorf("expected nil for unknown path, got %v", pkg)
	}
}

func TestPlaceholderRecognizers(t *testing.T) {
	if IsPANSource(nil) {
		t.Error("IsPANSource(nil) should be false")
	}
	if IsHardcodedKeySource(nil) {
		t.Error("IsHardcodedKeySource(nil) should be false")
	}
	if IsLoggerSink(nil) {
		t.Error("IsLoggerSink(nil) should be false")
	}
	if IsCryptoSink(nil) {
		t.Error("IsCryptoSink(nil) should be false")
	}
	if IsDBStoreSink(nil) {
		t.Error("IsDBStoreSink(nil) should be false")
	}
	if IsHTTPClientSink(nil) {
		t.Error("IsHTTPClientSink(nil) should be false")
	}
}
