package hybridcache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock { return &fakeClock{now: start} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestHybridCache_PutGet(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	entry := &Entry{Findings: []scanner.Finding{}}
	Put("sid-a", entry)
	got, ok := Get("sid-a")
	if !ok {
		t.Fatalf("expected session hit, got miss")
	}
	if got != entry {
		t.Fatalf("expected pointer-equal Entry, got different pointer")
	}
}

func TestHybridCache_TTLEvictionAt10Min(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	Put("sid-a", &Entry{Findings: []scanner.Finding{}})
	clk.Advance(10*time.Minute - time.Second)
	if _, ok := Get("sid-a"); !ok {
		t.Fatalf("session must survive 9m59s, got miss")
	}
	clk.Advance(2 * time.Second)
	if _, ok := Get("sid-a"); ok {
		t.Fatalf("session must expire at 10m+1s, still hit")
	}
	if _, ok := cache.Load("sid-a"); ok {
		t.Fatalf("expired entry must be lazy-deleted from sync.Map after Get miss")
	}
}

// TestHybridCache_TTL_ExactTenMinutes_Inclusive pins the boundary semantics
// documented in docs/tools.md ("10-minute TTL"): at exactly 10m+0ns the
// entry is still alive; at 10m+1ns it is gone. Guards against silent off-by-
// one drift if someone swaps After for Before without thinking.
func TestHybridCache_TTL_ExactTenMinutes_Inclusive(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	Put("sid-a", &Entry{Findings: []scanner.Finding{}})
	clk.Advance(SessionTTL)
	if _, ok := Get("sid-a"); !ok {
		t.Fatalf("entry must survive at exactly 10m (inclusive), got miss")
	}
	clk.Advance(time.Nanosecond)
	if _, ok := Get("sid-a"); ok {
		t.Fatalf("entry must be evicted past 10m (strictly after), still hit")
	}
}

func TestHybridCache_Concurrent(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	const goroutines = 100
	const opsPerG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				sid := fmt.Sprintf("sid-%d-%d", gid, i)
				Put(sid, &Entry{Findings: []scanner.Finding{}})
				if _, ok := Get(sid); !ok {
					t.Errorf("goroutine %d op %d: expected hit after put", gid, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestHybridCache_Thousand(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	for i := 0; i < 1000; i++ {
		Put(fmt.Sprintf("sid-%04d", i), &Entry{})
	}
	if n := CountForTest(); n != 1000 {
		t.Fatalf("expected 1000 entries before advance, got %d", n)
	}
	clk.Advance(SessionTTL + time.Second)
	EvictExpiredForTest()
	if n := CountForTest(); n != 0 {
		t.Fatalf("expected 0 entries after advance + evict, got %d", n)
	}
}

func TestHybridCache_CursorExpired_OnMiss(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	if entry, ok := Get("does-not-exist"); ok || entry != nil {
		t.Fatalf("expected (nil,false) on miss, got (%v,%v)", entry, ok)
	}
}

func TestSessionKey_Stability(t *testing.T) {
	k1 := SessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", true)
	k2 := SessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", true)
	if k1 != k2 {
		t.Fatalf("SessionKey must be deterministic: %q != %q", k1, k2)
	}
	if len(k1) != 16 {
		t.Fatalf("SessionKey must be 16 hex chars, got %d (%q)", len(k1), k1)
	}
	kTaintOff := SessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", false)
	if k1 == kTaintOff {
		t.Fatalf("taint flag must influence SessionKey")
	}
}

func TestFilterHash_Stability(t *testing.T) {
	h1 := FilterHash("HIGH", "PAN-*", true)
	h2 := FilterHash("HIGH", "PAN-*", true)
	if h1 != h2 {
		t.Fatalf("FilterHash must be deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 16 {
		t.Fatalf("FilterHash must be 16 hex chars, got %d (%q)", len(h1), h1)
	}
	if FilterHash("HIGH", "PAN-*", true) == FilterHash("HIGH", "PAN-*", false) {
		t.Fatalf("includeTests flag must influence FilterHash")
	}
}

func TestCursor_RoundTrip(t *testing.T) {
	p := CursorPayload{SID: "abc123", Off: 60, Tool: "scan_pan_data"}
	enc, err := EncodeCursor(p)
	if err != nil {
		t.Fatalf("EncodeCursor: %v", err)
	}
	got, err := DecodeCursor(enc)
	if err != nil {
		t.Fatalf("DecodeCursor: %v", err)
	}
	if got != p {
		t.Fatalf("round-trip mismatch: got %+v, want %+v", got, p)
	}
}

func TestDecodeCursor_Malformed(t *testing.T) {
	if _, err := DecodeCursor("not-a-cursor!@#"); err == nil {
		t.Fatalf("expected error for malformed cursor, got nil")
	}
}

func TestPutWithHistogram_GetReturnsSameSnapshot(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 20, 0, 0, 0, 0, time.UTC))
	Reset(clk)
	defer Reset(nil)

	findings := []scanner.Finding{
		{RuleID: "PAN-KEYWORD", Severity: scanner.SeverityHigh},
		{RuleID: "PAN-KEYWORD", Severity: scanner.SeverityHigh},
		{RuleID: "AUTH-MISSING-MFA", Severity: scanner.SeverityCritical},
	}
	hist := BuildHistogram(findings)
	meta := ScanMeta{TotalFiles: 7, TotalLines: 123, DurationMS: 42}
	PutWithHistogram("sid-h", findings, meta, &hist)

	gotFindings, gotMeta, gotHist, ok := GetWithHistogram("sid-h")
	if !ok {
		t.Fatalf("GetWithHistogram miss")
	}
	if len(gotFindings) != len(findings) {
		t.Fatalf("len(findings)=%d want %d", len(gotFindings), len(findings))
	}
	if gotMeta != meta {
		t.Errorf("meta mismatch: got=%+v want=%+v", gotMeta, meta)
	}
	if gotHist == nil {
		t.Fatalf("histogram snapshot lost on round-trip")
	}
	if gotHist.BySeverity.Critical != 1 || gotHist.BySeverity.High != 2 {
		t.Errorf("histogram severity mismatch: %+v", gotHist.BySeverity)
	}
	if len(gotHist.ByRule) != 2 {
		t.Fatalf("ByRule len=%d want 2", len(gotHist.ByRule))
	}

	e, legacyOK := Get("sid-h")
	if !legacyOK {
		t.Fatalf("legacy Get must still hit after PutWithHistogram")
	}
	if e.Histogram == nil {
		t.Errorf("Entry.Histogram must survive via legacy Get")
	}
}
