package authscanner

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const (
	s2sTagPrefix          = "downgrade:s2s_handler"
	s2sRequirementMachine = "8.6.1"
	s2sRequirementToken   = "8.6.2"
)

var handlerNameRE = regexp.MustCompile(
	`(?i)(Webhook|Callback|Notification|Event|Ipn|Notify)(Handler)?$|` +
		`(?i)Handle.*(Webhook|Callback|Notification|Event|Ipn)|` +
		`(?i)On.*(Event|Notification)|` +
		`(?i)Process.*(Notification|Event|Webhook|Callback)`,
)

var webhookPathRE = regexp.MustCompile(
	`(?i)/(webhook|webhooks|callback|callbacks|notifications|events|ipn|hooks|cb)(/|$)`,
)

var strongCallSignals = map[string]bool{
	"hmac.Equal":                              true,
	"subtle.ConstantTimeCompare":              true,
	"rsa.VerifyPKCS1v15":                      true,
	"rsa.VerifyPSS":                           true,
	"ecdsa.Verify":                            true,
	"ecdsa.VerifyASN1":                        true,
	"ed25519.Verify":                          true,
	"jwt.Parse":                               true,
	"jwt.ParseWithClaims":                     true,
	"jose.ParseSigned":                        true,
	"webhook.ConstructEvent":                  true,
	"webhook.ConstructEventIgnoringTolerance": true,
	"webhook.ConstructEventWithTolerance":     true,
	// Adyen API spelling is ValidateHmac (camel); both forms accepted
	// defensively in case in-tree code uses uppercase.
	"hmacvalidator.ValidateHmac":        true,
	"hmacvalidator.ValidateHmacPayload": true,
	"hmacvalidator.CalculateHmac":       true,
	"client.VerifyWebhookSignature":     true,
}

var jsonParserSelectors = map[string]bool{
	"json.Unmarshal":     true,
	"json.NewDecoder":    true,
	"xml.Unmarshal":      true,
	"proto.Unmarshal":    true,
	"yaml.Unmarshal":     true,
	"toml.Unmarshal":     true,
	"easyjson.Unmarshal": true,
}

type signalCounts struct {
	Strong            int
	Medium            int
	Weak              int
	HasNegativeSignal bool
	StrongHits        []string
	MediumHits        []string
	WeakHits          []string
}

func (sc signalCounts) isS2S() bool {
	if sc.HasNegativeSignal {
		return false
	}
	return sc.Strong >= 1 || (sc.Medium >= 2 && sc.Weak >= 1)
}

func (sc signalCounts) reason() string {
	parts := []string{}
	if len(sc.StrongHits) > 0 {
		parts = append(parts, "T1["+strings.Join(sc.StrongHits, ",")+"]")
	}
	if len(sc.MediumHits) > 0 {
		parts = append(parts, "T2["+strings.Join(sc.MediumHits, ",")+"]")
	}
	if len(sc.WeakHits) > 0 {
		parts = append(parts, "T3["+strings.Join(sc.WeakHits, ",")+"]")
	}
	if len(parts) == 0 {
		return "no signals"
	}
	return strings.Join(parts, " ")
}

func ApplyS2SDowngrade(findings []scanner.Finding, file *ast.File, fset *token.FileSet, path string) []scanner.Finding {
	if len(findings) == 0 || file == nil {
		return findings
	}
	signalsByHandler := buildHandlerSignalMap(file, fset)
	routeHandlerAtLine := buildRouteHandlerAtLineMap(file, fset)
	for i := range findings {
		f := &findings[i]
		if f.RuleID != "AUTH-MISSING-MFA" {
			continue
		}
		handlerName := handlerNameForFinding(file, fset, f, routeHandlerAtLine)
		if handlerName == "" {
			continue
		}
		sig, ok := signalsByHandler[handlerName]
		if !ok {
			continue
		}
		if !sig.isS2S() {
			continue
		}
		f.Severity = scanner.SeverityInfo
		f.TriageHint = s2sTagPrefix + " | " + sig.reason()
		f.RelatedRequirements = mergeRequirements(f.RelatedRequirements, s2sRequirementMachine, s2sRequirementToken)
		f.Description = f.Description + " [s2s_handler — machine-to-machine context, MFA per PCI 8.4.2 not applicable; verify machine auth per PCI 8.6.1/8.6.2]"
	}
	return findings
}

func buildHandlerSignalMap(file *ast.File, fset *token.FileSet) map[string]signalCounts {
	out := map[string]signalCounts{}
	routeMeta := buildRouteMeta(file)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}
		sc := computeHandlerSignals(fn, routeMeta[fn.Name.Name])
		out[fn.Name.Name] = sc
	}
	return out
}

type routeRegMeta struct {
	HasWebhookPath bool
	HasPostMethod  bool
	PathLiteral    string
}

func buildRouteMeta(file *ast.File) map[string]routeRegMeta {
	out := map[string]routeRegMeta{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		method := sel.Sel.Name
		if !routeRegistrationMethods[method] {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		pathLit := extractStringLiteral(call.Args[0])
		if pathLit == "" {
			return true
		}
		handlerName := extractHandlerIdent(call.Args[1])
		if handlerName == "" {
			return true
		}
		meta := out[handlerName]
		meta.PathLiteral = pathLit
		if webhookPathRE.MatchString(pathLit) {
			meta.HasWebhookPath = true
		}
		if method == "POST" || method == "Post" || method == "PUT" || method == "Put" {
			meta.HasPostMethod = true
		}
		out[handlerName] = meta
		return true
	})
	return out
}

func buildRouteHandlerAtLineMap(file *ast.File, fset *token.FileSet) map[int]string {
	out := map[int]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if !routeRegistrationMethods[sel.Sel.Name] {
			return true
		}
		if len(call.Args) < 2 {
			return true
		}
		handlerName := extractHandlerIdent(call.Args[1])
		if handlerName == "" {
			return true
		}
		pos := fset.Position(call.Pos())
		out[pos.Line] = handlerName
		return true
	})
	return out
}

func computeHandlerSignals(fn *ast.FuncDecl, route routeRegMeta) signalCounts {
	var sc signalCounts
	if handlerNameRE.MatchString(fn.Name.Name) {
		sc.Medium++
		sc.MediumHits = append(sc.MediumHits, "name_regex")
	}
	if route.HasWebhookPath {
		sc.Medium++
		sc.MediumHits = append(sc.MediumHits, "path:"+route.PathLiteral)
	}
	if route.HasPostMethod {
		sc.Medium++
		sc.MediumHits = append(sc.MediumHits, "method:POST")
	}
	walkBodyForSignals(fn.Body, &sc)
	return sc
}

func walkBodyForSignals(body *ast.BlockStmt, sc *signalCounts) {
	if body == nil {
		return
	}
	hasAuthHeaderRead := false
	hasJSONParser := false
	hasIOReadAll := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		name := callSelectorName(sel)
		if isSessionCookieWrite(call, sel) {
			sc.HasNegativeSignal = true
			return false
		}
		if strongCallSignals[name] {
			sc.Strong++
			sc.StrongHits = append(sc.StrongHits, name)
			return true
		}
		if name == "Header.Get" || name == "GetHeader" || sel.Sel.Name == "Get" {
			if argIsAuthHeaderLiteral(call.Args) {
				hasAuthHeaderRead = true
			}
		}
		if jsonParserSelectors[name] {
			hasJSONParser = true
		}
		if name == "io.ReadAll" || name == "ioutil.ReadAll" || name == "Context.GetRawData" || sel.Sel.Name == "GetRawData" {
			hasIOReadAll = true
		}
		return true
	})
	if !hasAuthHeaderRead {
		sc.Weak++
		sc.WeakHits = append(sc.WeakHits, "no_auth_header_read")
	}
	if hasIOReadAll && hasJSONParser {
		sc.Weak++
		sc.WeakHits = append(sc.WeakHits, "raw_body_then_parse")
	}
}

func callSelectorName(sel *ast.SelectorExpr) string {
	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name + "." + sel.Sel.Name
	}
	if inner, ok := sel.X.(*ast.SelectorExpr); ok {
		return inner.Sel.Name + "." + sel.Sel.Name
	}
	if call, ok := sel.X.(*ast.CallExpr); ok {
		if innerSel, ok2 := call.Fun.(*ast.SelectorExpr); ok2 {
			return innerSel.Sel.Name + "." + sel.Sel.Name
		}
	}
	return sel.Sel.Name
}

func argIsAuthHeaderLiteral(args []ast.Expr) bool {
	for _, a := range args {
		s := extractStringLiteral(a)
		if strings.EqualFold(s, "Authorization") {
			return true
		}
	}
	return false
}

func isSessionCookieWrite(call *ast.CallExpr, sel *ast.SelectorExpr) bool {
	method := sel.Sel.Name
	if method == "Save" || method == "Set" {
		if recvIdent, ok := sel.X.(*ast.Ident); ok {
			low := strings.ToLower(recvIdent.Name)
			if strings.HasPrefix(low, "session") || strings.HasPrefix(low, "sess") {
				return true
			}
		}
	}
	if method == "SetCookie" && len(call.Args) == 7 {
		return true
	}
	if method == "SetCookie" && len(call.Args) == 2 {
		if pkgIdent, ok := sel.X.(*ast.Ident); ok && pkgIdent.Name == "http" {
			return true
		}
	}
	if (method == "Set" || method == "Add") && len(call.Args) >= 2 {
		first := extractStringLiteral(call.Args[0])
		if strings.EqualFold(first, "Set-Cookie") {
			return true
		}
	}
	return false
}

func handlerNameForFinding(file *ast.File, fset *token.FileSet, f *scanner.Finding, routeHandlerAtLine map[int]string) string {
	if name, ok := routeHandlerAtLine[f.Line]; ok {
		return name
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil {
			continue
		}
		pos := fset.Position(fn.Pos())
		if pos.Line == f.Line {
			return fn.Name.Name
		}
	}
	return ""
}

func mergeRequirements(existing []string, add ...string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, r := range existing {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for _, r := range add {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}
