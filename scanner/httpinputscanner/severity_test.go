package httpinputscanner

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"testing"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

func TestClassifyKeyword(t *testing.T) {
	tt := []struct {
		name string
		id   string
		want severityClass
	}{
		{name: "pan -> PAN/CHD", id: "pan", want: severityClassPanCHD},
		{name: "primaryaccountnumber -> PAN/CHD", id: "primaryaccountnumber", want: severityClassPanCHD},
		{name: "card_number -> PAN/CHD", id: "card_number", want: severityClassPanCHD},
		{name: "Card_Number mixed case -> PAN/CHD", id: "Card_Number", want: severityClassPanCHD},
		{name: "cvv -> PAN/CHD", id: "cvv", want: severityClassPanCHD},
		{name: "CVC -> PAN/CHD", id: "CVC", want: severityClassPanCHD},
		{name: "iban -> PAN/CHD", id: "iban", want: severityClassPanCHD},
		{name: "IBAN upper -> PAN/CHD", id: "IBAN", want: severityClassPanCHD},
		{name: "AccountNumber -> PAN/CHD", id: "AccountNumber", want: severityClassPanCHD},
		{name: "securitycode -> PAN/CHD", id: "securitycode", want: severityClassPanCHD},

		{name: "apikey -> auth-secret", id: "apikey", want: severityClassAuthSecret},
		{name: "api_key -> auth-secret", id: "api_key", want: severityClassAuthSecret},
		{name: "API_Key mixed -> auth-secret", id: "API_Key", want: severityClassAuthSecret},
		{name: "password -> auth-secret", id: "password", want: severityClassAuthSecret},
		{name: "secret -> auth-secret", id: "secret", want: severityClassAuthSecret},
		{name: "bearer -> auth-secret", id: "bearer", want: severityClassAuthSecret},
		{name: "token -> none on source side (Plan 21.1-09 narrowing)", id: "token", want: severityClassNone},
		{name: "auth -> none on source side (Plan 21.1-09 narrowing)", id: "auth", want: severityClassNone},
		{name: "Authorization -> none on source side (Plan 21.1-09 narrowing)", id: "Authorization", want: severityClassNone},

		{name: "request_id -> generic-ID", id: "request_id", want: severityClassGenericID},
		{name: "requestid -> generic-ID", id: "requestid", want: severityClassGenericID},
		{name: "trace_id -> generic-ID", id: "trace_id", want: severityClassGenericID},
		{name: "traceid -> generic-ID", id: "traceid", want: severityClassGenericID},
		{name: "widget_id -> generic-ID", id: "widget_id", want: severityClassGenericID},
		{name: "widget-id dash -> generic-ID", id: "widget-id", want: severityClassGenericID},
		{name: "tenant_id -> generic-ID", id: "tenant_id", want: severityClassGenericID},
		{name: "merchant_id -> generic-ID", id: "merchant_id", want: severityClassGenericID},
		{name: "correlation_id -> generic-ID", id: "correlation_id", want: severityClassGenericID},
		{name: "correlationid -> generic-ID", id: "correlationid", want: severityClassGenericID},
		{name: "span_id -> generic-ID", id: "span_id", want: severityClassGenericID},
		{name: "spanid -> generic-ID", id: "spanid", want: severityClassGenericID},

		{name: "body -> none", id: "body", want: severityClassNone},
		{name: "value -> none", id: "value", want: severityClassNone},
		{name: "path -> none", id: "path", want: severityClassNone},
		{name: "email -> none", id: "email", want: severityClassNone},
		{name: "name -> none", id: "name", want: severityClassNone},
		{name: "query -> none", id: "query", want: severityClassNone},
		{name: "empty -> none", id: "", want: severityClassNone},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyKeyword(tc.id); got != tc.want {
				t.Fatalf("classifyKeyword(%q) = %d, want %d", tc.id, got, tc.want)
			}
		})
	}
}

func TestComputeSeverity(t *testing.T) {
	tt := []struct {
		name           string
		ctx            UserInputContext
		wantSeverity   scanner.Severity
		wantShouldEmit bool
	}{
		{
			name:           "pan keyword fires HIGH",
			ctx:            UserInputContext{Identifier: "pan"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "card_number keyword fires HIGH",
			ctx:            UserInputContext{Identifier: "card_number"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "iban keyword fires HIGH",
			ctx:            UserInputContext{Identifier: "iban"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "apikey keyword fires HIGH (auth-secret)",
			ctx:            UserInputContext{Identifier: "apikey"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "api_key keyword fires HIGH (auth-secret)",
			ctx:            UserInputContext{Identifier: "api_key"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "token source-side fires MEDIUM (Plan 21.1-09 narrowing)",
			ctx:            UserInputContext{Identifier: "token"},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "password keyword fires HIGH (auth-secret)",
			ctx:            UserInputContext{Identifier: "password"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "secret keyword fires HIGH (auth-secret)",
			ctx:            UserInputContext{Identifier: "secret"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "bearer keyword fires HIGH (auth-secret)",
			ctx:            UserInputContext{Identifier: "bearer"},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "Authorization source-side fires MEDIUM (Plan 21.1-09 narrowing)",
			ctx:            UserInputContext{Identifier: "Authorization"},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "request_id suppresses",
			ctx:            UserInputContext{Identifier: "request_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "widget_id suppresses",
			ctx:            UserInputContext{Identifier: "widget_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "trace_id suppresses",
			ctx:            UserInputContext{Identifier: "trace_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "tenant_id suppresses",
			ctx:            UserInputContext{Identifier: "tenant_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "merchant_id suppresses",
			ctx:            UserInputContext{Identifier: "merchant_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "correlation_id suppresses",
			ctx:            UserInputContext{Identifier: "correlation_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "span_id suppresses",
			ctx:            UserInputContext{Identifier: "span_id"},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "body identifier no body-decoder fires MEDIUM",
			ctx:            UserInputContext{Identifier: "body"},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "value identifier no body-decoder fires MEDIUM",
			ctx:            UserInputContext{Identifier: "value"},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "email identifier no body-decoder fires MEDIUM",
			ctx:            UserInputContext{Identifier: "email"},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "empty identifier no body-decoder fires MEDIUM",
			ctx:            UserInputContext{Identifier: ""},
			wantSeverity:   scanner.SeverityMedium,
			wantShouldEmit: true,
		},
		{
			name:           "body-source override fires HIGH on bare body identifier",
			ctx:            UserInputContext{Identifier: "body", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "body-source override fires HIGH on empty identifier",
			ctx:            UserInputContext{Identifier: "", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "auth-secret beats body-source override (api_key + body-decoder still HIGH)",
			ctx:            UserInputContext{Identifier: "api_key", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
		{
			name:           "generic-ID priority wins over body-source override",
			ctx:            UserInputContext{Identifier: "widget_id", SourceIsBodyDecoder: true},
			wantSeverity:   "",
			wantShouldEmit: false,
		},
		{
			name:           "PAN-CHD class beats body-source override",
			ctx:            UserInputContext{Identifier: "cvv", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			gotSev, gotEmit := computeSeverity(tc.ctx)
			if gotEmit != tc.wantShouldEmit {
				t.Fatalf("computeSeverity(%+v) shouldEmit = %v, want %v", tc.ctx, gotEmit, tc.wantShouldEmit)
			}
			if gotEmit && gotSev != tc.wantSeverity {
				t.Fatalf("computeSeverity(%+v) severity = %q, want %q", tc.ctx, gotSev, tc.wantSeverity)
			}
		})
	}
}

func TestRelatedRequirementsForLog(t *testing.T) {
	tt := []struct {
		name     string
		severity scanner.Severity
		ctx      UserInputContext
		want     []string
	}{
		{
			name:     "PAN-CHD HIGH returns 3.3.1 + 3.5.1",
			severity: scanner.SeverityHigh,
			ctx:      UserInputContext{Identifier: "pan"},
			want:     []string{"3.3.1", "3.5.1"},
		},
		{
			name:     "card_number HIGH returns 3.3.1 + 3.5.1",
			severity: scanner.SeverityHigh,
			ctx:      UserInputContext{Identifier: "card_number"},
			want:     []string{"3.3.1", "3.5.1"},
		},
		{
			name:     "auth-secret HIGH returns 8.6.2",
			severity: scanner.SeverityHigh,
			ctx:      UserInputContext{Identifier: "apikey"},
			want:     []string{"8.6.2"},
		},
		{
			name:     "api_key HIGH returns 8.6.2 (apikey reclassification)",
			severity: scanner.SeverityHigh,
			ctx:      UserInputContext{Identifier: "api_key"},
			want:     []string{"8.6.2"},
		},
		{
			name:     "token MEDIUM returns nil after Plan 21.1-09 narrowing",
			severity: scanner.SeverityMedium,
			ctx:      UserInputContext{Identifier: "token"},
			want:     nil,
		},
		{
			name:     "body-source HIGH returns nil (no canonical reqs)",
			severity: scanner.SeverityHigh,
			ctx:      UserInputContext{Identifier: "body", SourceIsBodyDecoder: true},
			want:     nil,
		},
		{
			name:     "MEDIUM never returns related reqs",
			severity: scanner.SeverityMedium,
			ctx:      UserInputContext{Identifier: "body"},
			want:     nil,
		},
		{
			name:     "MEDIUM with empty identifier returns nil",
			severity: scanner.SeverityMedium,
			ctx:      UserInputContext{Identifier: ""},
			want:     nil,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got := relatedRequirementsForLog(tc.severity, tc.ctx)
			if !equalStringSlices(got, tc.want) {
				t.Fatalf("relatedRequirementsForLog(%q, %+v) = %v, want %v", tc.severity, tc.ctx, got, tc.want)
			}
		})
	}
}

func TestApiKeyReclassification(t *testing.T) {
	tt := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "matchesPanKeyword(apikey) is FALSE after reclassification",
			run: func(t *testing.T) {
				if matchesPanKeyword("apikey") {
					t.Fatalf("matchesPanKeyword(\"apikey\") = true, want false (reclassified to auth-secret)")
				}
				if matchesPanKeyword("api_key") {
					t.Fatalf("matchesPanKeyword(\"api_key\") = true, want false (reclassified to auth-secret)")
				}
			},
		},
		{
			name: "classifyKeyword(apikey) is auth-secret",
			run: func(t *testing.T) {
				if got := classifyKeyword("apikey"); got != severityClassAuthSecret {
					t.Fatalf("classifyKeyword(\"apikey\") = %d, want severityClassAuthSecret (%d)", got, severityClassAuthSecret)
				}
			},
		},
		{
			name: "relatedRequirementsForLog for apikey returns 8.6.2 not 3.3.1+3.5.1",
			run: func(t *testing.T) {
				got := relatedRequirementsForLog(scanner.SeverityHigh, UserInputContext{Identifier: "apikey"})
				if !equalStringSlices(got, []string{"8.6.2"}) {
					t.Fatalf("relatedRequirementsForLog for apikey = %v, want [8.6.2]", got)
				}
			},
		},
		{
			name: "PAN keyword pan still returns 3.3.1+3.5.1 (regression guard)",
			run: func(t *testing.T) {
				got := relatedRequirementsForLog(scanner.SeverityHigh, UserInputContext{Identifier: "pan"})
				if !equalStringSlices(got, []string{"3.3.1", "3.5.1"}) {
					t.Fatalf("relatedRequirementsForLog for pan = %v, want [3.3.1 3.5.1]", got)
				}
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, tc.run)
	}
}

func TestBodySourceOverrideInteractionMatrix(t *testing.T) {
	tt := []struct {
		name           string
		ctx            UserInputContext
		wantSeverity   scanner.Severity
		wantShouldEmit bool
		wantRelated    []string
	}{
		{
			name:           "apikey + body-decoder: auth-secret class wins, HIGH + 8.6.2",
			ctx:            UserInputContext{Identifier: "apikey", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
			wantRelated:    []string{"8.6.2"},
		},
		{
			name:           "body field + body-decoder source: body-source override fires HIGH, no related reqs",
			ctx:            UserInputContext{Identifier: "body", SourceIsBodyDecoder: true},
			wantSeverity:   scanner.SeverityHigh,
			wantShouldEmit: true,
			wantRelated:    nil,
		},
		{
			name:           "widget_id + body-decoder: generic-ID priority suppresses",
			ctx:            UserInputContext{Identifier: "widget_id", SourceIsBodyDecoder: true},
			wantSeverity:   "",
			wantShouldEmit: false,
			wantRelated:    nil,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			gotSev, gotEmit := computeSeverity(tc.ctx)
			if gotEmit != tc.wantShouldEmit {
				t.Fatalf("computeSeverity(%+v) shouldEmit = %v, want %v", tc.ctx, gotEmit, tc.wantShouldEmit)
			}
			if !gotEmit {
				return
			}
			if gotSev != tc.wantSeverity {
				t.Fatalf("computeSeverity(%+v) severity = %q, want %q", tc.ctx, gotSev, tc.wantSeverity)
			}
			gotRel := relatedRequirementsForLog(gotSev, tc.ctx)
			if !equalStringSlices(gotRel, tc.wantRelated) {
				t.Fatalf("relatedRequirementsForLog = %v, want %v", gotRel, tc.wantRelated)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExtractSinkFieldKeyLiteralsShapes(t *testing.T) {
	tt := []struct {
		name      string
		src       string
		findFn    string
		findCall  func(call *ast.CallExpr, info *types.Info) bool
		wantKeys  []string
		wantClass []severityClass
	}{
		{
			name: "slog.Info variadic kv keys",
			src: `package main
import "log/slog"
func F() { slog.Info("auth", "api_key", "v") }
`,
			findCall: func(call *ast.CallExpr, info *types.Info) bool {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return false
				}
				return sel.Sel != nil && sel.Sel.Name == "Info"
			},
			wantKeys:  []string{"api_key"},
			wantClass: []severityClass{severityClassAuthSecret},
		},
		{
			name: "slog.String attr-builder key",
			src: `package main
import "log/slog"
func F() { slog.String("password", "v") }
`,
			findCall: func(call *ast.CallExpr, info *types.Info) bool {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return false
				}
				return sel.Sel != nil && sel.Sel.Name == "String"
			},
			wantKeys:  []string{"password"},
			wantClass: []severityClass{severityClassAuthSecret},
		},
		{
			name: "slog.String key 'token' is NOT promoted post Plan 21.1-09 narrowing",
			src: `package main
import "log/slog"
func F() { slog.String("token", "v") }
`,
			findCall: func(call *ast.CallExpr, info *types.Info) bool {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return false
				}
				return sel.Sel != nil && sel.Sel.Name == "String"
			},
			wantKeys:  []string{"token"},
			wantClass: nil,
		},
		{
			name: "slog.Info no PAN/auth key returns no classes",
			src: `package main
import "log/slog"
func F() { slog.Info("ok", "request_id", "v") }
`,
			findCall: func(call *ast.CallExpr, info *types.Info) bool {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return false
				}
				return sel.Sel != nil && sel.Sel.Name == "Info"
			},
			wantKeys:  []string{"request_id"},
			wantClass: []severityClass{severityClassGenericID},
		},
		{
			name: "slog.Any attr-builder card_number key is PanCHD",
			src: `package main
import "log/slog"
func F() { slog.Any("card_number", "v") }
`,
			findCall: func(call *ast.CallExpr, info *types.Info) bool {
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return false
				}
				return sel.Sel != nil && sel.Sel.Name == "Any"
			},
			wantKeys:  []string{"card_number"},
			wantClass: []severityClass{severityClassPanCHD},
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
				Types:      map[ast.Expr]types.TypeAndValue{},
				Defs:       map[*ast.Ident]types.Object{},
				Uses:       map[*ast.Ident]types.Object{},
				Selections: map[*ast.SelectorExpr]*types.Selection{},
			}
			if _, err := conf.Check("x", fset, []*ast.File{f}, info); err != nil {
				t.Skipf("typecheck (env-dependent): %v", err)
			}
			var found *ast.CallExpr
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if tc.findCall(call, info) {
					found = call
					return false
				}
				return true
			})
			if found == nil {
				t.Fatal("did not locate target call")
			}
			gotKeys := extractSinkFieldKeyLiterals(found, info)
			if !equalStringSlices(gotKeys, tc.wantKeys) {
				t.Fatalf("extractSinkFieldKeyLiterals = %v, want %v", gotKeys, tc.wantKeys)
			}
			gotClasses := classifySinkFieldKeys(found, info)
			if !equalSeverityClasses(gotClasses, tc.wantClass) {
				t.Fatalf("classifySinkFieldKeys = %v, want %v", gotClasses, tc.wantClass)
			}
		})
	}
}

func equalSeverityClasses(a, b []severityClass) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestClassifySinkFieldKeysNarrowedSet(t *testing.T) {
	t.Parallel()
	tt := []struct {
		key  string
		want severityClass
	}{
		{key: "api_key", want: severityClassAuthSecret},
		{key: "apikey", want: severityClassAuthSecret},
		{key: "password", want: severityClassAuthSecret},
		{key: "secret", want: severityClassAuthSecret},
		{key: "bearer", want: severityClassAuthSecret},
		{key: "token", want: severityClassNone},
		{key: "auth", want: severityClassNone},
		{key: "Authorization", want: severityClassNone},
		{key: "card_number", want: severityClassPanCHD},
		{key: "pan", want: severityClassPanCHD},
		{key: "request_id", want: severityClassGenericID},
		{key: "body", want: severityClassNone},
	}
	for _, tc := range tt {
		t.Run(tc.key, func(t *testing.T) {
			if got := classifyKeyword(tc.key); got != tc.want {
				t.Fatalf("classifyKeyword(%q) = %d, want %d", tc.key, got, tc.want)
			}
		})
	}
}

func TestHasOverrideClass(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		in   []severityClass
		want bool
	}{
		{name: "empty -> false", in: nil, want: false},
		{name: "all none -> false", in: []severityClass{severityClassNone, severityClassNone}, want: false},
		{name: "auth-secret -> true", in: []severityClass{severityClassAuthSecret}, want: true},
		{name: "PanCHD -> true", in: []severityClass{severityClassPanCHD}, want: true},
		{name: "generic-ID alone -> false", in: []severityClass{severityClassGenericID}, want: false},
		{name: "PanCHD + GenericID -> true", in: []severityClass{severityClassGenericID, severityClassPanCHD}, want: true},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasOverrideClass(tc.in); got != tc.want {
				t.Fatalf("hasOverrideClass(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
