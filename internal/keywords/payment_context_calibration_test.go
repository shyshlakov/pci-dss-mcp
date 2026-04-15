package keywords

// Calibration test.
//
// This test locks in the recall/precision characteristics of
// PaymentContextScore. Any future change to the signal weights, whitelist,
// or threshold MUST either keep this test passing or explicitly update the
// trim log in the header comment below, citing the empirical FP rate
// measured on the changed configuration.
//
// memory/private_notes. The synthetic fixtures below
// are deliberate stand-ins for external repos (gorilla/mux, cobra) — vendoring
// those would bloat go.mod for a test. The synthetic set reproduces the same
// function shapes: HTTP middleware, CLI command registration, tree/queue
// utilities, option structs, game logic.
//
// Frozen trim sequence (, apply in order if FP rate exceeds 0.5% on a
// new calibration project):
//
// 1. Reduce signal 6 weight from +2 to +1.
// 2. Remove /tokens/ from signal 6 whitelist.
// 3. Remove /tokens/ from signal 2 whitelist.
// 4. Remove /transaction/ from both whitelists.
// 5. Remove /order/ from both whitelists.
// 6. Remove /card/ from both whitelists.
// 7. Remove /invoice/ from both whitelists.
// 8. Set signal 6 weight to 0 (disable internal import signal entirely).
//
// NEVER trim below the core /payment/, /payments/, /billing/, /checkout/
// set in signal 2 — these are the irreducible minimum.
//
// Per-step target: each trim must reduce FP rate by >= 0.05% or be a
// meaningful recall trade. Trimming a whitelist entry that produces zero
// FPs is pure recall loss — skip it.

import (
	"strings"
	"testing"
)

type calibSpec struct {
	name    string
	dir     string
	imports []string
}

// paymentBaseline: synthetic payment functions. Target: IsPaymentContext
// true on at least 19 of 20 (≥ 95% recall).
var paymentBaseline = []calibSpec{
	{name: `func Execute(c *Card) {}`, dir: "internal/payment"},
	{name: `func HandleRequest(inv *Invoice) {}`, dir: "internal/billing"},
	{name: `func Capture(t *Transaction) {}`, dir: "internal/processor", imports: []string{"github.com/stripe/stripe-go/v72"}},
	{name: `func Authorize(c *Card) {}`, dir: "internal/gateway"},
	{name: `func Settle(ref string) {}`, dir: "internal/billing"},
	{name: `func Void(id string) {}`, dir: "internal/payments"},
	{name: `func Charge(amount int64) {}`, dir: "internal/api"},
	{name: `func Refund(id string) {}`, dir: "internal/checkout"},
	{name: `func Tokenize(pan string) {}`, dir: "internal/tokens"},
	{name: `func Detokenize(token string) {}`, dir: "internal/tokens"},
	{name: `func Process(ch *Charge) {}`, dir: "internal/transaction"},
	{name: `func Submit(o *Order) {}`, dir: "internal/order"},
	{name: `func Buy() {}`, dir: "internal/checkout"},
	{name: `func Sell() {}`, dir: "internal/checkout"},
	{name: `func Book() {}`, dir: "internal/order"},
	{name: `func Do(req struct{ PAN string }) string { return req.PAN }`, dir: "internal/svc"},
	{name: `func Run(ch *Checkout) {}`, dir: "internal/svc"},
	{name: `func Deliver(inv *Invoice) {}`, dir: "internal/billing"},
	{name: `func Handle() {}`, dir: "internal/payment"},
	{name: `func Proxy() {}`, dir: "internal/svc", imports: []string{"github.com/adyen/adyen-go-api-library/v7"}},
}

// nonPaymentBaseline: synthetic non-payment functions. Target: < 2/30 FPs.
// One FP is pre-accepted: DealHand() in pkg/game/card — the /card/ path
// collision is a deliberate recall-bias trade-off.
var nonPaymentBaseline = []calibSpec{
	{name: `func ServeHTTP(w http.ResponseWriter, r *http.Request) {}`, dir: "internal/middleware"},
	{name: `func Get(key string) string { return "" }`, dir: "internal/cache"},
	{name: `func Set(key, val string) {}`, dir: "internal/cache"},
	{name: `func Delete(key string) {}`, dir: "internal/cache"},
	{name: `func Push(v int) {}`, dir: "internal/stack"},
	{name: `func Pop() int { return 0 }`, dir: "internal/stack"},
	{name: `func Insert(node *Node) {}`, dir: "internal/tree"},
	{name: `func Search(key string) bool { return false }`, dir: "internal/tree"},
	{name: `func WriteToFile(data []byte) error { return nil }`, dir: "internal/util"},
	{name: `func ReadFromFile(path string) []byte { return nil }`, dir: "internal/util"},
	{name: `func ParseFlags(args []string) {}`, dir: "internal/cli"},
	{name: `func Register(cmd *Cmd) {}`, dir: "internal/cli"},
	{name: `func Connect(dsn string) error { return nil }`, dir: "internal/db"},
	{name: `func Query(sql string) []Row { return nil }`, dir: "internal/db"},
	{name: `func Begin() {}`, dir: "internal/db"},
	{name: `func Commit() {}`, dir: "internal/db"},
	{name: `func Rollback() {}`, dir: "internal/db"},
	{name: `func ServeWebSocket() {}`, dir: "internal/ws"},
	{name: `func Broadcast(msg string) {}`, dir: "internal/ws"},
	{name: `func Subscribe(topic string) chan string { return nil }`, dir: "internal/pubsub"},
	{name: `func Publish(topic, msg string) {}`, dir: "internal/pubsub"},
	{name: `func HealthCheck() bool { return true }`, dir: "internal/health"},
	{name: `func Version() string { return "1.0" }`, dir: "internal/version"},
	{name: `func NewUser(name string) *User { return nil }`, dir: "internal/user"},
	{name: `func Login(email, pass string) error { return nil }`, dir: "internal/auth"},
	{name: `func Logout() {}`, dir: "internal/auth"},
	{name: `func Authenticate(tok string) bool { return false }`, dir: "internal/auth"},
	{name: `func Encrypt(plaintext []byte) []byte { return nil }`, dir: "internal/crypto"},
	{name: `func Decrypt(ciphertext []byte) []byte { return nil }`, dir: "internal/crypto"},
	{name: `func DealHand() []int { return nil }`, dir: "pkg/game/card"},
}

// wrapTypes prepends minimal type declarations for any referenced named
// type so synthetic source fragments parse cleanly. Must run BEFORE
// parse; unresolved identifiers would otherwise abort.
func wrapTypes(src string) string {
	needed := []string{
		"Card", "Invoice", "Checkout", "Order", "Charge",
		"Transaction", "Node", "Cmd", "User", "Row",
	}
	var b strings.Builder
	for _, t := range needed {
		if strings.Contains(src, "*"+t) || strings.Contains(src, " "+t) {
			b.WriteString("type " + t + " struct{}\n")
		}
	}
	return b.String()
}

func buildCalibSrc(spec calibSpec) string {
	var b strings.Builder
	b.WriteString("package p\n")
	b.WriteString("import \"net/http\"\n")
	b.WriteString("var _ = http.StatusOK\n")
	b.WriteString(wrapTypes(spec.name))
	b.WriteString(spec.name)
	b.WriteString("\n")
	return b.String()
}

// scoreCalibSpec parses the synthetic fragment and returns the score +
// signal breakdown for spec. Under Option C each call constructs a
// fresh *PackageInfo via pkgWith, which produces an isolated scoreCache
// (or no cache at all when pkgWith returns a bare struct). No global
// reset is required because there is no global state.
func scoreCalibSpec(t *testing.T, spec calibSpec) (int, []string, bool) {
	t.Helper()
	src := buildCalibSrc(spec)
	fn, _ := parseFuncFromSrc(t, src)
	pkg := pkgWith(spec.dir, spec.imports...)
	score, sig := PaymentContextScoreWithBreakdown(fn, pkg)
	return score, sig, IsPaymentContext(fn, pkg)
}

func TestPaymentBaselineRecall(t *testing.T) {
	passed := 0
	for _, spec := range paymentBaseline {
		score, sig, ctx := scoreCalibSpec(t, spec)
		if ctx {
			passed++
			continue
		}
		t.Logf("MISS: %q dir=%q score=%d signals=%v", spec.name, spec.dir, score, sig)
	}
	recall := float64(passed) / float64(len(paymentBaseline))
	t.Logf("calibration recall = %.2f%% (%d/%d)", recall*100, passed, len(paymentBaseline))
	if recall < 0.95 {
		t.Errorf("recall = %.2f%% (%d/%d), want >= 95%% — do NOT lower the bar, investigate which signal failed",
			recall*100, passed, len(paymentBaseline))
	}
}

func TestNonPaymentBaselineFPGuard(t *testing.T) {
	fpCount := 0
	for _, spec := range nonPaymentBaseline {
		score, sig, ctx := scoreCalibSpec(t, spec)
		if ctx {
			fpCount++
			t.Logf("FP: %q dir=%q score=%d signals=%v", spec.name, spec.dir, score, sig)
		}
	}
	// Target: <= 2 FPs across 30 cases (6.66%). Recall-bias: the /card/
	// path collision with card-game projects is a deliberate trade-off.
	// If FPs exceed 2, apply the trim sequence in the header comment —
	// do not simply raise this ceiling.
	fpRate := float64(fpCount) / float64(len(nonPaymentBaseline))
	t.Logf("calibration FP rate = %.2f%% (%d/%d)", fpRate*100, fpCount, len(nonPaymentBaseline))
	if fpCount > 2 {
		t.Errorf("false positives = %d/%d, want <= 2 — apply trim sequence", fpCount, len(nonPaymentBaseline))
	}
}

// TestCoreWhitelistFrozen guards the irreducible core of the payment
// path whitelist. Any future trim MUST NOT touch these four segments.
func TestCoreWhitelistFrozen(t *testing.T) {
	core := []string{"/payment", "/payments", "/billing", "/checkout"}
	for _, c := range core {
		found := false
		for _, seg := range SharedPathWhitelist {
			if seg == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("core whitelist segment %q missing from SharedPathWhitelist — NEVER trim below the core per ", c)
		}
	}
	t.Logf("core whitelist frozen: %v (full whitelist: %v)", core, SharedPathWhitelist)
}
