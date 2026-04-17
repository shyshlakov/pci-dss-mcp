// Package hybridcache provides the session cache and cursor encoding used by
// the three MCP tools (generate_compliance_report, triage_findings,
// scan_pan_data) to share paginated results. It sits below reportscanner,
// panscanner, and triagescanner so those packages can share a single
// sync.Map-backed cache without import cycles.
package hybridcache

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

const (
	SessionTTL    = 10 * time.Minute
	EvictInterval = 60 * time.Second
)

type Entry struct {
	Findings  []scanner.Finding
	Meta      ScanMeta
	CreatedAt time.Time
	ExpiresAt time.Time
}

type ScanMeta struct {
	TotalFiles int
	TotalLines int
	DurationMS int64
}

var (
	mu           sync.Mutex
	cache        sync.Map
	clockPtr     atomic.Pointer[Clock]
	evictorOnce  sync.Once
	evictorStop  chan struct{}
	evictorDone  chan struct{}
)

func init() {
	var c Clock = realClock{}
	clockPtr.Store(&c)
}

func loadClock() Clock {
	if p := clockPtr.Load(); p != nil {
		return *p
	}
	return realClock{}
}

func storeClock(c Clock) {
	if c == nil {
		c = realClock{}
	}
	clockPtr.Store(&c)
}

func startEvictor() {
	evictorOnce.Do(func() {
		stop := make(chan struct{})
		done := make(chan struct{})
		mu.Lock()
		evictorStop = stop
		evictorDone = done
		mu.Unlock()
		go func() {
			defer close(done)
			ticker := time.NewTicker(EvictInterval)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					evictExpired()
				}
			}
		}()
	})
}

func evictExpired() {
	now := loadClock().Now()
	cache.Range(func(k, v any) bool {
		entry, ok := v.(*Entry)
		if !ok {
			cache.Delete(k)
			return true
		}
		if now.After(entry.ExpiresAt) {
			cache.Delete(k)
		}
		return true
	})
}

func EvictExpiredForTest() { evictExpired() }

func SessionKey(projectRoot, scanTimestampRFC3339, fh string, includeTaint bool) string {
	taint := "0"
	if includeTaint {
		taint = "1"
	}
	h := sha256.New()
	h.Write([]byte(projectRoot))
	h.Write([]byte{0})
	h.Write([]byte(scanTimestampRFC3339))
	h.Write([]byte{0})
	h.Write([]byte(fh))
	h.Write([]byte{0})
	h.Write([]byte(taint))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func FilterHash(minSeverity, ruleFilter string, includeTests bool) string {
	h := sha256.New()
	h.Write([]byte(minSeverity))
	h.Write([]byte("|"))
	h.Write([]byte(ruleFilter))
	h.Write([]byte("|"))
	b := 0
	if includeTests {
		b = 1
	}
	h.Write([]byte(strconv.Itoa(b)))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func Put(sid string, entry *Entry) {
	now := loadClock().Now()
	entry.CreatedAt = now
	entry.ExpiresAt = now.Add(SessionTTL)
	cache.Store(sid, entry)
	startEvictor()
}

func Get(sid string) (*Entry, bool) {
	v, ok := cache.Load(sid)
	if !ok {
		return nil, false
	}
	entry, ok := v.(*Entry)
	if !ok {
		cache.Delete(sid)
		return nil, false
	}
	if loadClock().Now().After(entry.ExpiresAt) {
		cache.Delete(sid)
		return nil, false
	}
	return entry, true
}

// Reset clears the cache and swaps in the provided clock. Passing nil restores
// the default wall-clock. Intended for tests that use a fake clock. Blocks
// until the background evictor goroutine (if any) has drained so tests cannot
// observe a lingering sweep under -race.
func Reset(c Clock) {
	mu.Lock()
	stop := evictorStop
	done := evictorDone
	evictorStop = nil
	evictorDone = nil
	evictorOnce = sync.Once{}
	mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}

	cache.Range(func(k, _ any) bool {
		cache.Delete(k)
		return true
	})
	storeClock(c)
}

// SetClockForTest swaps in a fake clock without clearing entries.
func SetClockForTest(c Clock) {
	storeClock(c)
}

// CountForTest returns the number of entries currently held by the cache.
func CountForTest() int {
	n := 0
	cache.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

type CursorPayload struct {
	SID  string `json:"sid"`
	Off  int    `json:"off"`
	Tool string `json:"tool,omitempty"`
}

func EncodeCursor(p CursorPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("cursor_malformed: marshal: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func DecodeCursor(s string) (CursorPayload, error) {
	var p CursorPayload
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return p, fmt.Errorf("cursor_malformed: base64: %w", err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("cursor_malformed: json: %w", err)
	}
	return p, nil
}
