package httpinputscanner

import (
	"context"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestScannerIdentity(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "Name returns http_input_taint",
			run: func(t *testing.T) {
				s := New()
				if got := s.Name(); got != "http_input_taint" {
					t.Fatalf("Name() = %q, want http_input_taint", got)
				}
			},
		},
		{
			name: "Description is non-empty",
			run: func(t *testing.T) {
				s := New()
				if s.Description() == "" {
					t.Fatal("Description() empty")
				}
			},
		},
		{
			name: "Requirements include 10.2.1 6.2.4 3.3.1 3.5.1",
			run: func(t *testing.T) {
				s := New()
				want := map[string]bool{"10.2.1": false, "6.2.4": false, "3.3.1": false, "3.5.1": false}
				for _, r := range s.Requirements() {
					want[r] = true
				}
				for k, v := range want {
					if !v {
						t.Fatalf("Requirements() missing %q", k)
					}
				}
			},
		},
		{
			name: "Scan returns INFO HTTP-INPUT-TAINT-OFF when taint disabled",
			run: func(t *testing.T) {
				s := New()
				result, err := s.Scan(context.Background(), t.TempDir())
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if len(result.Findings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(result.Findings))
				}
				f := result.Findings[0]
				if f.RuleID != "HTTP-INPUT-TAINT-OFF" {
					t.Fatalf("RuleID = %q, want HTTP-INPUT-TAINT-OFF", f.RuleID)
				}
				if f.Severity != scanner.SeverityInfo {
					t.Fatalf("Severity = %q, want INFO", f.Severity)
				}
			},
		},
		{
			name: "satisfies scanner.Scanner interface",
			run: func(t *testing.T) {
				var _ scanner.Scanner = New()
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}

func TestPanKeywordSeverity(t *testing.T) {
	tt := []struct {
		name           string
		ctx            UserInputContext
		wantSeverity   scanner.Severity
		wantShouldEmit bool
	}{
		{name: "pan promotes to HIGH", ctx: UserInputContext{Identifier: "pan"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "card promotes to HIGH", ctx: UserInputContext{Identifier: "card_number"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "cvv promotes to HIGH", ctx: UserInputContext{Identifier: "cvv"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "iban promotes to HIGH", ctx: UserInputContext{Identifier: "IBAN"}, wantSeverity: scanner.SeverityHigh, wantShouldEmit: true},
		{name: "bin stays MEDIUM", ctx: UserInputContext{Identifier: "bin"}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
		{name: "user stays MEDIUM", ctx: UserInputContext{Identifier: "user"}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
		{name: "empty stays MEDIUM", ctx: UserInputContext{Identifier: ""}, wantSeverity: scanner.SeverityMedium, wantShouldEmit: true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			gotSev, gotEmit := computeSeverity(tc.ctx)
			if gotEmit != tc.wantShouldEmit {
				t.Fatalf("computeSeverity(%q) shouldEmit = %v, want %v", tc.ctx.Identifier, gotEmit, tc.wantShouldEmit)
			}
			if gotEmit && gotSev != tc.wantSeverity {
				t.Fatalf("computeSeverity(%q) = %q, want %q", tc.ctx.Identifier, gotSev, tc.wantSeverity)
			}
		})
	}
}

func TestTriageHintFor(t *testing.T) {
	tt := []struct {
		ruleID string
		want   string
	}{
		{ruleID: "HTTP-INPUT-LOG", want: "http-input-leak"},
		{ruleID: "HTTP-INPUT-ERROR", want: "framework-input-error"},
		{ruleID: "HTTP-INPUT-PANIC", want: "recovery-leak"},
		{ruleID: "OTHER", want: ""},
	}
	for _, tc := range tt {
		t.Run(tc.ruleID, func(t *testing.T) {
			if got := triageHintFor(tc.ruleID); got != tc.want {
				t.Fatalf("triageHintFor(%q) = %q, want %q", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestSafeIdentifierFiltering(t *testing.T) {
	tt := []struct {
		name string
		id   string
		want bool
	}{
		{name: "X-Request-ID is safe", id: "X-Request-ID", want: true},
		{name: "user-agent lowercase is safe", id: "user-agent", want: true},
		{name: "X-Trace-Id is safe", id: "X-Trace-Id", want: true},
		{name: "Authorization is unsafe", id: "Authorization", want: false},
		{name: "token is unsafe", id: "token", want: false},
		{name: "empty is unsafe", id: "", want: false},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSafeIdentifier(tc.id); got != tc.want {
				t.Fatalf("isSafeIdentifier(%q) = %v, want %v", tc.id, got, tc.want)
			}
		})
	}
}

func TestFmtVerbInvokesStringer(t *testing.T) {
	tt := []struct {
		name      string
		formatStr string
		argIdx    int
		want      bool
	}{
		{name: "%v invokes", formatStr: "value: %v", argIdx: 0, want: true},
		{name: "%s invokes", formatStr: "value: %s", argIdx: 0, want: true},
		{name: "%w invokes", formatStr: "wrap: %w", argIdx: 0, want: true},
		{name: "%d numeric does not", formatStr: "count: %d", argIdx: 0, want: false},
		{name: "%x hex does not", formatStr: "hex: %x", argIdx: 0, want: false},
		{name: "%o octal does not", formatStr: "octal: %o", argIdx: 0, want: false},
		{name: "%q quote does not", formatStr: "quoted: %q", argIdx: 0, want: false},
		{name: "%t bool does not", formatStr: "flag: %t", argIdx: 0, want: false},
		{name: "%f float does not", formatStr: "amt: %f", argIdx: 0, want: false},
		{name: "+v flag tolerated", formatStr: "verbose: %+v", argIdx: 0, want: true},
		{name: "width modifier tolerated", formatStr: "padded: %10s", argIdx: 0, want: true},
		{name: "left-align width tolerated", formatStr: "padded: %-10s", argIdx: 0, want: true},
		{name: "precision tolerated", formatStr: "prec: %.5s", argIdx: 0, want: true},
		{name: "width.precision tolerated", formatStr: "prec: %5.2f", argIdx: 0, want: false},
		{name: "second arg %s after %d", formatStr: "[%d] %s", argIdx: 1, want: true},
		{name: "first arg %d after literal", formatStr: "n=%d v=%v", argIdx: 1, want: true},
		{name: "first arg %d", formatStr: "n=%d v=%v", argIdx: 0, want: false},
		{name: "%% escape skipped, then %s at idx 0", formatStr: "100%% done %s", argIdx: 0, want: true},
		{name: "%% escape skipped, %d at idx 0", formatStr: "100%% done %d", argIdx: 0, want: false},
		{name: "argIdx out of range", formatStr: "no verbs here", argIdx: 0, want: false},
		{name: "argIdx beyond verb count", formatStr: "only %s", argIdx: 1, want: false},
		{name: "mixed verbs %+v %5.2f %-10s, idx 0 v", formatStr: "%+v %5.2f %-10s", argIdx: 0, want: true},
		{name: "mixed verbs idx 1 f", formatStr: "%+v %5.2f %-10s", argIdx: 1, want: false},
		{name: "mixed verbs idx 2 s", formatStr: "%+v %5.2f %-10s", argIdx: 2, want: true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := verbInvokesStringer(tc.formatStr, tc.argIdx)
			if got != tc.want {
				t.Fatalf("verbInvokesStringer(%q, %d) = %v, want %v", tc.formatStr, tc.argIdx, got, tc.want)
			}
		})
	}
}

func TestImplementsStringer(t *testing.T) {
	tt := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "value receiver String() string",
			src: `package x
type T struct{}
func (T) String() string { return "" }
func F() { var _ T }
`,
			want: true,
		},
		{
			name: "pointer receiver String() string",
			src: `package x
type T struct{}
func (*T) String() string { return "" }
func F() { var _ T }
`,
			want: true,
		},
		{
			name: "no String method",
			src: `package x
type T struct{}
func F() { var _ T }
`,
			want: false,
		},
		{
			name: "String returning non-string",
			src: `package x
type T struct{}
func (T) String() int { return 0 }
func F() { var _ T }
`,
			want: false,
		},
		{
			name: "String with params",
			src: `package x
type T struct{}
func (T) String(prefix string) string { return prefix }
func F() { var _ T }
`,
			want: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "x.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			conf := types.Config{Importer: importer.Default()}
			info := &types.Info{
				Defs: map[*ast.Ident]types.Object{},
			}
			if _, err := conf.Check("x", fset, []*ast.File{f}, info); err != nil {
				t.Skipf("typecheck (env-dependent): %v", err)
			}
			var typ types.Type
			for id, obj := range info.Defs {
				if obj == nil {
					continue
				}
				if id.Name == "T" {
					if tn, ok := obj.(*types.TypeName); ok {
						typ = tn.Type()
						break
					}
				}
			}
			if typ == nil {
				t.Fatal("did not find type T")
			}
			got := implementsStringer(typ)
			if got != tc.want {
				t.Fatalf("implementsStringer(T) = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestImplementsStringerNil(t *testing.T) {
	if implementsStringer(nil) {
		t.Fatal("implementsStringer(nil) should be false")
	}
}

func TestIsFmtErrorfVerbStringerEndToEnd(t *testing.T) {
	tt := []struct {
		name      string
		src       string
		wantMatch bool
	}{
		{
			name: "fmt.Errorf %v on Stringer-typed tainted ident matches",
			src: `package main
import "fmt"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() {
	t := Token{raw: "x"}
	_ = fmt.Errorf("token invalid: %v", t)
}
`,
			wantMatch: true,
		},
		{
			name: "fmt.Sprintf %s on Stringer-typed tainted ident matches",
			src: `package main
import "fmt"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() {
	t := Token{raw: "x"}
	_ = fmt.Sprintf("payload %s", t)
}
`,
			wantMatch: true,
		},
		{
			name: "fmt.Errorf %d on Stringer-typed arg does NOT match (numeric verb)",
			src: `package main
import "fmt"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() {
	t := Token{raw: "x"}
	_ = fmt.Errorf("count: %d", t)
}
`,
			wantMatch: false,
		},
		{
			name: "fmt.Errorf %s on plain string ident does NOT match (no Stringer)",
			src: `package main
import "fmt"
func F() {
	x := "hello"
	_ = fmt.Errorf("%s", x)
}
`,
			wantMatch: false,
		},
		{
			name: "variable format string does NOT match",
			src: `package main
import "fmt"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() {
	t := Token{raw: "x"}
	fmtStr := "token: %v"
	_ = fmt.Errorf(fmtStr, t)
}
`,
			wantMatch: false,
		},
		{
			name: "non-fmt callee does NOT match",
			src: `package main
import "strings"
type Token struct{ raw string }
func (t Token) String() string { return t.raw }
func F() {
	t := Token{raw: "x"}
	_ = strings.Join([]string{t.String()}, ",")
}
`,
			wantMatch: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "p.go", tc.src, 0)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			conf := types.Config{Importer: importer.Default()}
			info := &types.Info{
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			pkg, err := conf.Check("main", fset, []*ast.File{f}, info)
			if err != nil {
				t.Skipf("typecheck (env-dependent): %v", err)
			}
			st := newFileState(nil, f, info)
			st.pkg = nil
			// Inject taint for the local identifier `t` (or `x`) so the
			// classifyExpr fall-through reaches the verb-aware check with a
			// tainted variable. Mimics what an upstream USER_INPUT source
			// would seed in production.
			seedCtx := UserInputContext{Identifier: "Authorization", Framework: "gin"}
			for id, obj := range info.Defs {
				if obj == nil {
					continue
				}
				if id.Name == "t" || id.Name == "x" {
					if v, ok := obj.(*types.Var); ok {
						st.taintedIdents[v] = taintMeta{source: seedCtx}
					}
				}
			}
			var found *ast.CallExpr
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				switch id.Name + "." + sel.Sel.Name {
				case "fmt.Errorf", "fmt.Sprintf", "strings.Join":
					found = call
					return false
				}
				return true
			})
			if found == nil {
				t.Fatal("did not find target call expression")
			}
			got := isFmtErrorfVerbStringer(found, info, st)
			if got != tc.wantMatch {
				t.Fatalf("isFmtErrorfVerbStringer = %v, want %v (pkg=%s)", got, tc.wantMatch, pkg.Path())
			}
		})
	}
}

func TestIsFmtErrorfVerbStringerNilGuards(t *testing.T) {
	if isFmtErrorfVerbStringer(nil, nil, nil) {
		t.Fatal("isFmtErrorfVerbStringer(nil, nil, nil) returned true")
	}
	info := &types.Info{}
	if isFmtErrorfVerbStringer(nil, info, nil) {
		t.Fatal("isFmtErrorfVerbStringer(nil, info, nil) returned true")
	}
	call := &ast.CallExpr{}
	if isFmtErrorfVerbStringer(call, nil, nil) {
		t.Fatal("isFmtErrorfVerbStringer(call, nil, nil) returned true")
	}
}

func TestFmtVerbRegexShape(t *testing.T) {
	tt := []struct {
		input string
		want  []string
	}{
		{input: "%v", want: []string{"v"}},
		{input: "%s", want: []string{"s"}},
		{input: "%w", want: []string{"w"}},
		{input: "%d", want: []string{"d"}},
		{input: "%+v", want: []string{"v"}},
		{input: "%-10s", want: []string{"s"}},
		{input: "%5.2f", want: []string{"f"}},
		{input: "%v %s %d", want: []string{"v", "s", "d"}},
		{input: "no verbs", want: nil},
	}
	for _, tc := range tt {
		t.Run(tc.input, func(t *testing.T) {
			matches := fmtVerbRegex.FindAllStringSubmatch(tc.input, -1)
			if len(matches) != len(tc.want) {
				t.Fatalf("matches count = %d, want %d for %q", len(matches), len(tc.want), tc.input)
			}
			for i := range matches {
				if matches[i][1] != tc.want[i] {
					t.Fatalf("match[%d] = %q, want %q for input %q", i, matches[i][1], tc.want[i], tc.input)
				}
			}
		})
	}
}
