package keywords

// Multi-signal payment-context scorer. Replaces the legacy keyword-only
// gate that missed abstract handler names (Exchange, Execute, HandleRequest).
// Biases toward recall — accepts a few false positives on non-payment
// codebases because (a) the AI triage step filters noise before it reaches
// the user and (b) silent false negatives are catastrophic for PCI DSS
// compliance.

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"strings"
)

// PackageInfo carries static metadata about the package being scanned so
// the scorer can evaluate non-function-name signals without re-parsing
// the AST. Scanners build this once per package and pass it to
// PaymentContextScore / IsPaymentContext.
type PackageInfo struct {
	ImportPath string
	Dir        string
	Imports    map[string]bool
	Files      []*ast.File
	fset       *token.FileSet
	scoreCache map[string]cachedScore
}

// PaymentContextThreshold is the minimum score for IsPaymentContext to
// return true. Any single strong signal from triggers on its own;
// the threshold is deliberately permissive to favor recall over precision.
const PaymentContextThreshold = 2

// SharedPathWhitelist is the set of package-path segments treated as
// payment context by signals 2 (own path) and 6 (imported path).
// Recall-biased starting point.
var SharedPathWhitelist = []string{
	"/payment",
	"/payments",
	"/billing",
	"/checkout",
	"/card",
	"/invoice",
	"/tokens",
	"/transaction",
	"/order",
}

// SHARED_WHITELIST is a legacy alias kept for backward compatibility.
// Prefer the Go-idiomatic SharedPathWhitelist in new code.
var SHARED_WHITELIST = SharedPathWhitelist

// PaymentSDKSubstrings are import-path substrings indicating an external
// payment SDK dependency (signal 3, +3 weight).
var PaymentSDKSubstrings = []string{
	"stripe",
	"paypal",
	"go-jose/go-jose",
	"braintree-go-sdk",
	"square/connect",
	"razorpay",
	"mollie",
	"adyen",
	"plaid",
	"checkout.com",
}

// CHDTypeNames are type-name substrings (case-insensitive) treated as
// cardholder-data types for signal 4.
var CHDTypeNames = []string{
	"card",
	"pan",
	"token",
	"payment",
	"transaction",
	"invoice",
	"charge",
	"checkout",
}

// CHDFieldNames are selector field names treated as cardholder-data
// access for signal 5 (case-insensitive substring match on
// *ast.SelectorExpr.Sel.Name).
var CHDFieldNames = []string{
	"pan",
	"cvv",
	"cardnumber",
	"cardnum",
	"expiry",
	"expirydate",
	"cvc",
	"cardholder",
}

// PaymentContextScore returns the weighted multi-signal payment-context
// score for fn. Any score >= PaymentContextThreshold means the function
// should be treated as payment context by scanners. Passing a nil pkg
// is safe: non-package signals still evaluate.
func PaymentContextScore(fn *ast.FuncDecl, pkg *PackageInfo) int {
	score, _ := paymentContextScoreInternal(fn, pkg)
	return score
}

// PaymentContextScoreWithBreakdown returns the score plus a list of
// signal names that fired ("name", "path", "sdk", "chd-param",
// "chd-field", "internal-import"). Used by tests and the future
// --debug-context-score flag.
func PaymentContextScoreWithBreakdown(fn *ast.FuncDecl, pkg *PackageInfo) (int, []string) {
	return paymentContextScoreInternal(fn, pkg)
}

// IsPaymentContext reports whether fn should be treated as payment context.
func IsPaymentContext(fn *ast.FuncDecl, pkg *PackageInfo) bool {
	return PaymentContextScore(fn, pkg) >= PaymentContextThreshold
}

// cachedScore is a per-PackageInfo memoization entry for
// paymentContextScoreInternal. The cache lives on PackageInfo.scoreCache,
// so each scan session gets a fresh cache and no global state is needed.
type cachedScore struct {
	score   int
	signals []string
}

// scoreCacheKey derives a collision-free cache key for fn within pkg.
// Composite format: absolute-filename + "#" + receiverType + "." + funcName.
// Including the receiver type prevents two same-name methods on different
// receivers (e.g. (*CardRepo).Create and (*OrderRepo).Create co-located in
// the same file) from colliding in the per-package score cache. (.)
func scoreCacheKey(fn *ast.FuncDecl, fset *token.FileSet) string {
	if fn == nil || fn.Name == nil {
		return ""
	}
	var recv string
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		recv = receiverTypeName(fn.Recv.List[0].Type)
	}
	filename := ""
	if fset != nil {
		filename = fset.Position(fn.Pos()).Filename
	}
	return filename + "#" + recv + "." + fn.Name.Name
}

// receiverTypeName returns a stable string for a receiver type expression.
// Unlike typeExprName it preserves the pointer/generic shape so that
// (*T).M and T.M (or T[X].M and T[Y].M) get distinct cache keys.
func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if inner := receiverTypeName(t.X); inner != "" {
			return "*" + inner
		}
	case *ast.IndexExpr:
		return receiverTypeName(t.X) + "[]"
	case *ast.IndexListExpr:
		return receiverTypeName(t.X) + "[]"
	}
	return ""
}

func paymentContextScoreInternal(fn *ast.FuncDecl, pkg *PackageInfo) (int, []string) {
	if fn == nil || fn.Name == nil {
		return 0, nil
	}
	var key string
	if pkg != nil && pkg.scoreCache != nil {
		key = scoreCacheKey(fn, pkg.fset)
		if key != "" {
			if cs, ok := pkg.scoreCache[key]; ok {
				return cs.score, cs.signals
			}
		}
	}

	score := 0
	var signals []string

	// Signal 1: function name keyword match (+2).
	if matchesPaymentFuncKeyword(fn.Name.Name) {
		score += 2
		signals = append(signals, "name")
	}

	// Signal 2: own package path segment in SharedPathWhitelist (+2).
	if pkg != nil && pkg.Dir != "" {
		dirLower := strings.ToLower(pkg.Dir)
		if !strings.HasPrefix(dirLower, "/") {
			dirLower = "/" + dirLower
		}
		for _, seg := range SharedPathWhitelist {
			if strings.Contains(dirLower, seg) {
				score += 2
				signals = append(signals, "path")
				break
			}
		}
	}

	// Signal 3: external payment SDK import (+3).
	if pkg != nil && hasSDKImport(pkg.Imports) {
		score += 3
		signals = append(signals, "sdk")
	}

	// Signal 4: CHD-typed parameter or local variable (+2).
	if chdTypeInSignature(fn) || chdTypeInLocals(fn) {
		score += 2
		signals = append(signals, "chd-param")
	}

	// Signal 5: CHD field access in body (+2).
	if chdFieldInBody(fn) {
		score += 2
		signals = append(signals, "chd-field")
	}

	// Signal 6: internal payment-package import (+2). Shares the
	// whitelist with signal 2.
	if pkg != nil && hasInternalPaymentImport(pkg.Imports) {
		score += 2
		signals = append(signals, "internal-import")
	}

	if pkg != nil && pkg.scoreCache != nil && key != "" {
		pkg.scoreCache[key] = cachedScore{score: score, signals: signals}
	}
	return score, signals
}

func hasSDKImport(imports map[string]bool) bool {
	if len(imports) == 0 {
		return false
	}
	for imp := range imports {
		impLower := strings.ToLower(imp)
		for _, sub := range PaymentSDKSubstrings {
			if strings.Contains(impLower, sub) {
				return true
			}
		}
	}
	return false
}

func hasInternalPaymentImport(imports map[string]bool) bool {
	if len(imports) == 0 {
		return false
	}
	for imp := range imports {
		impLower := strings.ToLower(imp)
		for _, seg := range SharedPathWhitelist {
			if strings.Contains(impLower, seg) {
				return true
			}
		}
	}
	return false
}

// chdTypeInSignature walks fn.Type.Params looking for a referenced type
// whose name matches CHDTypeNames (case-insensitive substring).
func chdTypeInSignature(fn *ast.FuncDecl) bool {
	if fn.Type == nil || fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if typeExprMatchesCHD(field.Type) {
			return true
		}
	}
	return false
}

// chdTypeInLocals walks fn.Body for *ast.ValueSpec with a declared type
// matching CHDTypeNames.
func chdTypeInLocals(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		if v, ok := n.(*ast.ValueSpec); ok {
			if v.Type != nil && typeExprMatchesCHD(v.Type) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

func typeExprMatchesCHD(expr ast.Expr) bool {
	name := typeExprName(expr)
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	for _, kw := range CHDTypeNames {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func typeExprName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.StarExpr:
		return typeExprName(e.X)
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.ArrayType:
		return typeExprName(e.Elt)
	}
	return ""
}

// chdFieldInBody walks fn.Body for SelectorExpr whose Sel.Name contains
// a CHDFieldNames substring (case-insensitive).
func chdFieldInBody(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil {
			return true
		}
		lower := strings.ToLower(sel.Sel.Name)
		for _, kw := range CHDFieldNames {
			if strings.Contains(lower, kw) {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// PackageInfoFromFile constructs a minimal PackageInfo from a single
// parsed file. Used by scanners that have not yet migrated to the
// packageContextAware interface. Dir is populated from the path argument
// so signal 2 (own-package path match against SharedPathWhitelist) fires
// without callers having to manually stamp it. scoreCache is initialized
// per-instance so each scan session gets a fresh memoization table
// no global state, no manual cache-reset sync required. Safe to call
// with a nil file.
func PackageInfoFromFile(file *ast.File, fset *token.FileSet, path string) *PackageInfo {
	dir := filepath.ToSlash(filepath.Dir(path))
	if file == nil {
		return &PackageInfo{
			Imports:    map[string]bool{},
			Dir:        dir,
			fset:       fset,
			scoreCache: map[string]cachedScore{},
		}
	}
	imports := make(map[string]bool, len(file.Imports))
	for _, imp := range file.Imports {
		if imp.Path == nil {
			continue
		}
		importPath := imp.Path.Value
		if len(importPath) >= 2 && importPath[0] == '"' && importPath[len(importPath)-1] == '"' {
			importPath = importPath[1 : len(importPath)-1]
		}
		imports[importPath] = true
	}
	return &PackageInfo{
		ImportPath: "",
		Dir:        dir,
		Imports:    imports,
		Files:      []*ast.File{file},
		fset:       fset,
		scoreCache: map[string]cachedScore{},
	}
}
