package reportscanner

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

const (
	sessionTTL    = 10 * time.Minute
	evictInterval = 60 * time.Second
)

var (
	sessionMu     sync.Mutex
	sessionCache  sync.Map
	sessionClkPtr atomic.Pointer[Clock]
	evictorOnce   sync.Once
	evictorStop   chan struct{}
	evictorDone   chan struct{}
)

func init() {
	var c Clock = realClock{}
	sessionClkPtr.Store(&c)
}

func loadSessionClock() Clock {
	if p := sessionClkPtr.Load(); p != nil {
		return *p
	}
	return realClock{}
}

func storeSessionClock(c Clock) {
	if c == nil {
		c = realClock{}
	}
	sessionClkPtr.Store(&c)
}

func startEvictor() {
	evictorOnce.Do(func() {
		stop := make(chan struct{})
		done := make(chan struct{})
		sessionMu.Lock()
		evictorStop = stop
		evictorDone = done
		sessionMu.Unlock()
		go func() {
			defer close(done)
			ticker := time.NewTicker(evictInterval)
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
	now := loadSessionClock().Now()
	sessionCache.Range(func(k, v any) bool {
		entry, ok := v.(*cacheEntry)
		if !ok {
			sessionCache.Delete(k)
			return true
		}
		if now.After(entry.expiresAt) {
			sessionCache.Delete(k)
		}
		return true
	})
}

// evictExpiredForTest invokes the same sweep used by the background evictor,
// so tests that advance a fake clock do not need to wait evictInterval.
func evictExpiredForTest() { evictExpired() }

func sessionKey(projectRoot, scanTimestampRFC3339, fh string, includeTaint bool) string {
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

func filterHash(minSeverity, ruleFilter string, includeTests bool) string {
	h := sha256.New()
	h.Write([]byte(minSeverity))
	h.Write([]byte("|"))
	h.Write([]byte(ruleFilter))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.Itoa(boolToInt(includeTests))))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func putSession(sid string, entry *cacheEntry) {
	now := loadSessionClock().Now()
	entry.createdAt = now
	entry.expiresAt = now.Add(sessionTTL)
	sessionCache.Store(sid, entry)
	startEvictor()
}

func getSession(sid string) (*cacheEntry, bool) {
	v, ok := sessionCache.Load(sid)
	if !ok {
		return nil, false
	}
	entry, ok := v.(*cacheEntry)
	if !ok {
		sessionCache.Delete(sid)
		return nil, false
	}
	if loadSessionClock().Now().After(entry.expiresAt) {
		sessionCache.Delete(sid)
		return nil, false
	}
	return entry, true
}

// ResetSessionCacheForTest clears the session cache and swaps in the provided
// clock. Tests call this at the start of each subtest so fake-clock TTL
// assertions stay deterministic. Blocks until the background evictor
// goroutine (if any) has drained so tests cannot observe a lingering sweep
// under -race.
func ResetSessionCacheForTest(c Clock) {
	sessionMu.Lock()
	stop := evictorStop
	done := evictorDone
	evictorStop = nil
	evictorDone = nil
	evictorOnce = sync.Once{}
	sessionMu.Unlock()

	if stop != nil {
		close(stop)
	}
	if done != nil {
		<-done
	}

	sessionCache.Range(func(k, _ any) bool {
		sessionCache.Delete(k)
		return true
	})
	storeSessionClock(c)
}
