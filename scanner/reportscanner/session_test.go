package reportscanner

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
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

func countSessionCache() int {
	n := 0
	sessionCache.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func TestSessionCache_PutGet(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	entry := &cacheEntry{findings: []ReportFinding{}}
	putSession("sid-a", entry)
	got, ok := getSession("sid-a")
	if !ok {
		t.Fatalf("expected session hit, got miss")
	}
	if got != entry {
		t.Fatalf("expected pointer-equal cacheEntry, got different pointer")
	}
}

func TestSessionTTLEvictionAt10Min(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	putSession("sid-a", &cacheEntry{findings: []ReportFinding{}})
	clk.Advance(10*time.Minute - time.Second)
	if _, ok := getSession("sid-a"); !ok {
		t.Fatalf("session must survive 9m59s, got miss")
	}
	clk.Advance(2 * time.Second)
	if _, ok := getSession("sid-a"); ok {
		t.Fatalf("session must expire at 10m+1s, still hit")
	}
	if _, ok := sessionCache.Load("sid-a"); ok {
		t.Fatalf("expired entry must be lazy-deleted from sync.Map after getSession miss")
	}
}

// TestSessionTTL_ExactTenMinutes_Inclusive pins the boundary semantics
// promised by docs/tools.md ("10-minute TTL"): at exactly 10m+0ns the entry
// is still alive, and at 10m+1ns it is gone. Guards the strict After check
// in getSession against silent off-by-one drift.
func TestSessionTTL_ExactTenMinutes_Inclusive(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	putSession("sid-a", &cacheEntry{findings: []ReportFinding{}})
	clk.Advance(sessionTTL)
	if _, ok := getSession("sid-a"); !ok {
		t.Fatalf("entry must survive at exactly 10m (inclusive), got miss")
	}
	clk.Advance(time.Nanosecond)
	if _, ok := getSession("sid-a"); ok {
		t.Fatalf("entry must be evicted past 10m (strictly after), still hit")
	}
}

func TestSessionCache_Concurrent(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	const goroutines = 100
	const opsPerG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				sid := fmt.Sprintf("sid-%d-%d", gid, i)
				putSession(sid, &cacheEntry{findings: []ReportFinding{}})
				if _, ok := getSession(sid); !ok {
					t.Errorf("goroutine %d op %d: expected hit after put", gid, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestSessionCache_CursorExpired_OnMiss(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	if entry, ok := getSession("does-not-exist"); ok || entry != nil {
		t.Fatalf("expected (nil,false) on miss, got (%v,%v)", entry, ok)
	}
}

func TestSessionCache_Thousand(t *testing.T) {
	clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
	ResetSessionCacheForTest(clk)
	for i := 0; i < 1000; i++ {
		putSession(fmt.Sprintf("sid-%04d", i), &cacheEntry{findings: nil})
	}
	if n := countSessionCache(); n != 1000 {
		t.Fatalf("expected 1000 entries before advance, got %d", n)
	}
	clk.Advance(sessionTTL + time.Second)
	evictExpiredForTest()
	if n := countSessionCache(); n != 0 {
		t.Fatalf("expected 0 entries after advance + evict, got %d", n)
	}
}

func TestSessionCache_Thousand_NoFlake(t *testing.T) {
	for trial := 0; trial < 10; trial++ {
		trial := trial
		t.Run(fmt.Sprintf("trial-%d", trial), func(t *testing.T) {
			clk := newFakeClock(time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC))
			ResetSessionCacheForTest(clk)

			var m0, m1 runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&m0)

			for i := 0; i < 1000; i++ {
				putSession(fmt.Sprintf("sid-%04d", i), &cacheEntry{findings: nil})
			}

			runtime.ReadMemStats(&m1)
			t.Logf("alloc delta for 1000 entries: %d bytes", int64(m1.TotalAlloc)-int64(m0.TotalAlloc))

			if n := countSessionCache(); n != 1000 {
				t.Fatalf("trial %d: expected 1000 entries before advance, got %d", trial, n)
			}
			clk.Advance(sessionTTL + time.Second)
			evictExpiredForTest()
			if n := countSessionCache(); n != 0 {
				t.Fatalf("trial %d: expected 0 entries after advance + evict, got %d", trial, n)
			}
		})
	}
}

func TestSessionKey_Stability(t *testing.T) {
	t.Parallel()
	k1 := sessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", true)
	k2 := sessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", true)
	if k1 != k2 {
		t.Fatalf("sessionKey must be deterministic: %q != %q", k1, k2)
	}
	if len(k1) != 16 {
		t.Fatalf("sessionKey must be 16 hex chars, got %d (%q)", len(k1), k1)
	}
	kTaintOff := sessionKey("/a/b", "2026-04-17T00:00:00Z", "fh1", false)
	if k1 == kTaintOff {
		t.Fatalf("taint flag must influence sessionKey")
	}
}

func TestFilterHash_Stability(t *testing.T) {
	t.Parallel()
	h1 := filterHash("HIGH", "PAN-*", true)
	h2 := filterHash("HIGH", "PAN-*", true)
	if h1 != h2 {
		t.Fatalf("filterHash must be deterministic: %q != %q", h1, h2)
	}
	if len(h1) != 16 {
		t.Fatalf("filterHash must be 16 hex chars, got %d (%q)", len(h1), h1)
	}
	if filterHash("HIGH", "PAN-*", true) == filterHash("HIGH", "PAN-*", false) {
		t.Fatalf("includeTests flag must influence filterHash")
	}
}
