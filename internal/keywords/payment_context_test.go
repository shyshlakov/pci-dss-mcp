package keywords

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func parseFuncFromSrc(t *testing.T, src string) (*ast.FuncDecl, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "test.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			return fn, fset
		}
	}
	t.Fatalf("no FuncDecl in src")
	return nil, nil
}

func pkgWith(dir string, imports ...string) *PackageInfo {
	m := map[string]bool{}
	for _, i := range imports {
		m[i] = true
	}
	return &PackageInfo{Dir: dir, Imports: m}
}

func containsSignal(signals []string, want string) bool {
	for _, s := range signals {
		if s == want {
			return true
		}
	}
	return false
}

// Layer 1 — signal isolation. One entry per signal asserting both weight
// and breakdown label.
func TestScoreSignalIsolation(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		pkg       *PackageInfo
		wantScore int
		wantLbl   string
	}{
		{
			name:      "signal 1 — function name keyword",
			src:       `package p; func Pay() {}`,
			pkg:       pkgWith(""),
			wantScore: 2,
			wantLbl:   "name",
		},
		{
			name:      "signal 2 — own package path",
			src:       `package p; func Foo() {}`,
			pkg:       pkgWith("internal/payment"),
			wantScore: 2,
			wantLbl:   "path",
		},
		{
			name:      "signal 3 — payment SDK import",
			src:       `package p; func Foo() {}`,
			pkg:       pkgWith("", "github.com/stripe/stripe-go/v72"),
			wantScore: 3,
			wantLbl:   "sdk",
		},
		{
			name:      "signal 4 — CHD param type",
			src:       `package p; type Card struct{}; func Execute(c *Card) {}`,
			pkg:       pkgWith(""),
			wantScore: 2,
			wantLbl:   "chd-param",
		},
		{
			name:      "signal 5 — CHD field access",
			src:       `package p; type req struct{ PAN string }; func Do(r req) string { return r.PAN }`,
			pkg:       pkgWith(""),
			wantScore: 2,
			wantLbl:   "chd-field",
		},
		{
			name:      "signal 6 — internal payment package import",
			src:       `package p; func Foo() {}`,
			pkg:       pkgWith("", "github.com/acme/app/internal/billing"),
			wantScore: 2,
			wantLbl:   "internal-import",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, _ := parseFuncFromSrc(t, tt.src)
			score, sig := PaymentContextScoreWithBreakdown(fn, tt.pkg)
			if score != tt.wantScore {
				t.Errorf("score = %d, want %d (signals=%v)", score, tt.wantScore, sig)
			}
			if !containsSignal(sig, tt.wantLbl) {
				t.Errorf("signals = %v, want contains %q", sig, tt.wantLbl)
			}
		})
	}
}

// Layer 2 — combined real-world shapes.
func TestScoreCombinedSignals(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		pkg     *PackageInfo
		wantGE  int
		wantCtx bool
	}{
		{
			name:    "abstract name in payment package",
			src:     `package p; type Service struct{}; func (s *Service) Execute() {}`,
			pkg:     pkgWith("internal/payment"),
			wantGE:  2,
			wantCtx: true,
		},
		{
			name:    "handler with CHD param in util",
			src:     `package p; type Card struct{}; func Handle(card *Card) {}`,
			pkg:     pkgWith("internal/util"),
			wantGE:  2,
			wantCtx: true,
		},
		{
			name:    "full combo — name + path + field",
			src:     `package p; type req struct{ PAN string }; func Charge(r req) string { return r.PAN }`,
			pkg:     pkgWith("internal/billing"),
			wantGE:  6,
			wantCtx: true,
		},
		{
			name:    "random utility — no signals",
			src:     `package p; func WriteBytes(b []byte) int { return len(b) }`,
			pkg:     pkgWith("internal/io"),
			wantGE:  0,
			wantCtx: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, _ := parseFuncFromSrc(t, tt.src)
			score, sig := PaymentContextScoreWithBreakdown(fn, tt.pkg)
			if score < tt.wantGE {
				t.Errorf("score = %d, want >= %d (signals=%v)", score, tt.wantGE, sig)
			}
			got := IsPaymentContext(fn, tt.pkg)
			if got != tt.wantCtx {
				t.Errorf("IsPaymentContext = %v, want %v (score=%d)", got, tt.wantCtx, score)
			}
		})
	}
}

// Layer 3 — negative cases (false positive prevention).
func TestScoreNegativeCases(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		pkg     *PackageInfo
		wantCtx bool
	}{
		{
			name:    "generic HTTP handler no CHD",
			src:     `package p; import "net/http"; func HandleRequest(w http.ResponseWriter, r *http.Request) {}`,
			pkg:     pkgWith("internal/middleware"),
			wantCtx: false,
		},
		{
			name:    "utility function",
			src:     `package p; import "os"; func WriteToFile(f *os.File, data []byte) error { return nil }`,
			pkg:     pkgWith("internal/util"),
			wantCtx: false,
		},
		{
			name: "comment with card keyword does not score",
			src: `package p
// handles card number processing
func Noop() {}`,
			pkg:     pkgWith("internal/util"),
			wantCtx: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn, _ := parseFuncFromSrc(t, tt.src)
			got := IsPaymentContext(fn, tt.pkg)
			if got != tt.wantCtx {
				score, sig := PaymentContextScoreWithBreakdown(fn, tt.pkg)
				t.Errorf("IsPaymentContext = %v, want %v (score=%d signals=%v)",
					got, tt.wantCtx, score, sig)
			}
		})
	}
}

// TestScoreCacheIsolation verifies that two independent PackageInfo
// instances maintain independent score caches. This is the per-instance
// isolation invariant that replaces the global cache-reset dance from
// the deprecated 19.2 API — each scan session gets its own cache
// automatically.
func TestScoreCacheIsolation(t *testing.T) {
	fset := token.NewFileSet()
	src := `package p; func Foo() {}`
	file, err := parser.ParseFile(fset, "a.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn = f
			break
		}
	}
	if fn == nil {
		t.Fatal("no FuncDecl")
	}

	pkgPayment := PackageInfoFromFile(file, fset, "internal/payment/a.go")
	pkgUtil := PackageInfoFromFile(file, fset, "internal/util/a.go")

	scorePayment := PaymentContextScore(fn, pkgPayment)
	scoreUtil := PaymentContextScore(fn, pkgUtil)

	if scorePayment < PaymentContextThreshold {
		t.Errorf("payment pkg score = %d, want >= %d", scorePayment, PaymentContextThreshold)
	}
	if scoreUtil >= PaymentContextThreshold {
		t.Errorf("util pkg score = %d, want < %d (no cache leakage)", scoreUtil, PaymentContextThreshold)
	}
	if len(pkgPayment.scoreCache) == 0 {
		t.Error("payment pkg scoreCache is empty — memoization not wired")
	}
	if len(pkgUtil.scoreCache) == 0 {
		t.Error("util pkg scoreCache is empty — memoization not wired")
	}
}

func TestPackageInfoFromFile(t *testing.T) {
	fset := token.NewFileSet()
	src := `package p
import (
	"github.com/stripe/stripe-go/v72"
	"net/http"
)
func Foo() {}
`
	file, err := parser.ParseFile(fset, "test.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pkg := PackageInfoFromFile(file, fset, "internal/billing/test.go")
	if pkg == nil {
		t.Fatal("PackageInfoFromFile returned nil")
	}
	if !pkg.Imports["github.com/stripe/stripe-go/v72"] {
		t.Errorf("missing stripe import: %v", pkg.Imports)
	}
	if !pkg.Imports["net/http"] {
		t.Errorf("missing net/http import: %v", pkg.Imports)
	}
	if pkg.Dir != "internal/billing" {
		t.Errorf("Dir = %q, want %q (constructor must populate from path arg)", pkg.Dir, "internal/billing")
	}
	nilPkg := PackageInfoFromFile(nil, fset, "internal/billing/other.go")
	if nilPkg == nil || nilPkg.Imports == nil {
		t.Errorf("nil-file branch must return non-nil PackageInfo with non-nil Imports, got %+v", nilPkg)
	}
	if nilPkg.Dir != "internal/billing" {
		t.Errorf("nil-file Dir = %q, want %q", nilPkg.Dir, "internal/billing")
	}
}

// TestScoreCacheDistinguishesMethodsBySharedName guards:
// two methods with the same simple name on different receiver types
// declared in the same file must not collide in PackageInfo.scoreCache.
// Pre-fix the cache key was filename#funcName, so the second method
// returned the first method's stale score (FP and FN both directions).
func TestScoreCacheDistinguishesMethodsBySharedName(t *testing.T) {
	const src = `package p

type Card struct{ Number string }

type CardRepo struct{}
type OrderRepo struct{}

func (r *CardRepo) Create(card *Card)   {}
func (r *OrderRepo) Create(name string) {}
`

	parseAndCollect := func(t *testing.T) (*PackageInfo, *ast.FuncDecl, *ast.FuncDecl) {
		t.Helper()
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "repo.go", src, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		pkg := PackageInfoFromFile(file, fset, "/some/path/repository/repo.go")

		var cardCreate, orderCreate *ast.FuncDecl
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || len(fn.Recv.List) == 0 || fn.Name == nil || fn.Name.Name != "Create" {
				continue
			}
			recvName := typeExprName(fn.Recv.List[0].Type)
			switch recvName {
			case "CardRepo":
				cardCreate = fn
			case "OrderRepo":
				orderCreate = fn
			}
		}
		if cardCreate == nil || orderCreate == nil {
			t.Fatalf("expected Create methods on both *CardRepo and *OrderRepo (cardCreate=%v orderCreate=%v)", cardCreate, orderCreate)
		}
		return pkg, cardCreate, orderCreate
	}

	t.Run("card then order", func(t *testing.T) {
		pkg, cardCreate, orderCreate := parseAndCollect(t)
		scoreCard := PaymentContextScore(cardCreate, pkg)
		scoreOrder := PaymentContextScore(orderCreate, pkg)
		if scoreCard == scoreOrder {
			t.Fatalf("cache collision: (*CardRepo).Create score=%d == (*OrderRepo).Create score=%d (expected distinct scores; the OrderRepo method must not inherit CardRepo's cached score)", scoreCard, scoreOrder)
		}
		if scoreCard < PaymentContextThreshold {
			t.Errorf("(*CardRepo).Create score=%d, want >= %d (chd-param signal expected)", scoreCard, PaymentContextThreshold)
		}
		if scoreOrder >= PaymentContextThreshold {
			t.Errorf("(*OrderRepo).Create score=%d, want < %d (no payment signals)", scoreOrder, PaymentContextThreshold)
		}
	})

	t.Run("order then card", func(t *testing.T) {
		pkg, cardCreate, orderCreate := parseAndCollect(t)
		scoreOrder := PaymentContextScore(orderCreate, pkg)
		scoreCard := PaymentContextScore(cardCreate, pkg)
		if scoreCard == scoreOrder {
			t.Fatalf("cache collision in reverse order: (*OrderRepo).Create score=%d == (*CardRepo).Create score=%d (expected distinct scores; the CardRepo method must not inherit OrderRepo's cached score)", scoreOrder, scoreCard)
		}
		if scoreCard < PaymentContextThreshold {
			t.Errorf("(*CardRepo).Create score=%d, want >= %d", scoreCard, PaymentContextThreshold)
		}
		if scoreOrder >= PaymentContextThreshold {
			t.Errorf("(*OrderRepo).Create score=%d, want < %d", scoreOrder, PaymentContextThreshold)
		}
	})
}
