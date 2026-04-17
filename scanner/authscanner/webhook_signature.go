package authscanner

import (
	"fmt"
	"go/ast"
	"go/token"
	"regexp"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

const (
	RuleAuthWebhookNoSignature = "AUTH-WEBHOOK-NO-SIGNATURE"
	RuleAuthWebhookVerified    = "AUTH-WEBHOOK-VERIFIED"

	webhookVerifiedTag = "webhook_signature_verified"
	webhookReqPrimary  = "6.2.4"
	webhookReqCHD      = "4.2.1"
)

var brandKeywordList = []string{
	"stripe", "adyen", "mdes", "mastercard", "paypal", "visa", "cybersource",
	"apple-pay", "applepay", "google-pay", "googlepay", "checkout", "worldpay",
	"square", "braintree", "fiserv",
}

// brandPathRE requires the brand keyword to appear after a webhook-route
// prefix segment; scoping prevents false matches on unrelated paths like
// /checkout/done where the brand keyword coincides with an unrelated page.
var brandPathRE = func() *regexp.Regexp {
	prefixes := `(webhooks?|callbacks?|notifications?|hooks|cb|ipn|events)`
	brands := strings.Join(brandKeywordList, "|")
	return regexp.MustCompile(`(?i)/` + prefixes + `/[^/]*(` + brands + `)`)
}()

var bodyParserSelectors = map[string]bool{
	"json.Unmarshal":     true,
	"xml.Unmarshal":      true,
	"proto.Unmarshal":    true,
	"yaml.Unmarshal":     true,
	"toml.Unmarshal":     true,
	"easyjson.Unmarshal": true,
}

var bodyParserMethods = map[string]bool{
	"ShouldBind":     true,
	"ShouldBindJSON": true,
	"ShouldBindXML":  true,
	"ShouldBindYAML": true,
	"Bind":           true,
	"BindJSON":       true,
	"BindXML":        true,
	"Decode":         true,
}

var verifyHelperRE = regexp.MustCompile(`(?i)^(verify|validate|authenticate)|(?i)check.*sig`)

func WebhookSignatureScan(file *ast.File, fset *token.FileSet, path, projectRoot string) []scanner.Finding {
	_ = projectRoot
	if file == nil {
		return nil
	}
	routeMeta := buildRouteMeta(file)
	pkgFuncs := collectFileFuncs(file)
	var findings []scanner.Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Body == nil {
			continue
		}
		route := routeMeta[fn.Name.Name]
		if !isWebhookCandidate(fn.Name.Name, route) {
			continue
		}
		parserPos, parserSelector := firstBodyParserPos(fn.Body)
		if parserPos == token.NoPos {
			continue
		}
		verified, hit := signatureVerifiedBeforeParser(fn.Body, parserPos, pkgFuncs)
		if !verified {
			if HasSignatureMiddlewareCoverage(path, fn.Name.Name) {
				verified = true
				hit = "middleware:HasSignatureMiddlewareCoverage"
			}
		}
		pos := fset.Position(fn.Pos())
		if verified {
			findings = append(findings, scanner.Finding{
				RuleID:        RuleAuthWebhookVerified,
				Severity:      scanner.SeverityInfo,
				RequirementID: webhookReqPrimary,
				FilePath:      path,
				Line:          pos.Line,
				Column:        pos.Column,
				Description:   fmt.Sprintf("Webhook handler %s verifies signature via %s before body parse %s. Audit trail.", fn.Name.Name, hit, parserSelector),
				Suggestion:    "Verified-OK marker. Confirm secret loaded from env (not source) and signature compare uses constant-time API.",
				TriageHint:    webhookVerifiedTag + " | " + hit,
			})
			continue
		}
		severity := scanner.SeverityHigh
		var related []string
		if isBrandPath(route.PathLiteral) || filePathHasBrandKeyword(path) {
			severity = scanner.SeverityCritical
			related = []string{webhookReqCHD}
		}
		findings = append(findings, scanner.Finding{
			RuleID:              RuleAuthWebhookNoSignature,
			Severity:            severity,
			RequirementID:       webhookReqPrimary,
			RelatedRequirements: related,
			FilePath:            path,
			Line:                pos.Line,
			Column:              pos.Column,
			Description:         fmt.Sprintf("Webhook handler %s parses request body via %s without prior signature verification. Forged-payload risk per PCI 6.2.4.", fn.Name.Name, parserSelector),
			Suggestion:          "Verify request signature (HMAC, JWS, RSA, or brand SDK ConstructEvent) BEFORE body parse. Use crypto/hmac.Equal or subtle.ConstantTimeCompare for comparison.",
		})
	}
	return findings
}

func isWebhookCandidate(name string, route routeRegMeta) bool {
	if handlerNameRE.MatchString(name) {
		return true
	}
	if route.HasWebhookPath {
		return true
	}
	if isBrandPath(route.PathLiteral) {
		return true
	}
	return false
}

func isBrandPath(routePath string) bool {
	if routePath == "" {
		return false
	}
	return brandPathRE.MatchString(routePath)
}

func firstBodyParserPos(body *ast.BlockStmt) (token.Pos, string) {
	pos := token.NoPos
	tag := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if pos != token.NoPos {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		name := callSelectorName(sel)
		if bodyParserSelectors[name] {
			pos = call.Pos()
			tag = name
			return false
		}
		if bodyParserMethods[sel.Sel.Name] {
			pos = call.Pos()
			tag = sel.Sel.Name
			return false
		}
		return true
	})
	return pos, tag
}

func signatureVerifiedBeforeParser(body *ast.BlockStmt, parserPos token.Pos, pkgFuncs map[string]*ast.FuncDecl) (bool, string) {
	verified := false
	hit := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if verified {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callPos := call.Pos()
		if callPos >= parserPos {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			name := callSelectorName(fn)
			if strongCallSignals[name] {
				verified = true
				hit = name
				return false
			}
			if strongCallSignals[fn.Sel.Name] {
				verified = true
				hit = fn.Sel.Name
				return false
			}
		case *ast.Ident:
			if !verifyHelperRE.MatchString(fn.Name) {
				return true
			}
			helper, ok := pkgFuncs[fn.Name]
			if !ok || helper.Body == nil {
				return true
			}
			visited := map[string]bool{fn.Name: true}
			if v, h := helperCallsStrongSignal(helper.Body, pkgFuncs, visited, 0); v {
				verified = true
				hit = "helper:" + fn.Name + "->" + h
				return false
			}
		}
		return true
	})
	return verified, hit
}

func helperCallsStrongSignal(body *ast.BlockStmt, pkgFuncs map[string]*ast.FuncDecl, visited map[string]bool, depthBudget int) (bool, string) {
	if body == nil {
		return false, ""
	}
	verified := false
	hit := ""
	ast.Inspect(body, func(n ast.Node) bool {
		if verified {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			name := callSelectorName(fn)
			if strongCallSignals[name] {
				verified = true
				hit = name
				return false
			}
			if strongCallSignals[fn.Sel.Name] {
				verified = true
				hit = fn.Sel.Name
				return false
			}
		case *ast.Ident:
			if depthBudget <= 0 || visited[fn.Name] {
				return true
			}
			helper, ok := pkgFuncs[fn.Name]
			if !ok || helper.Body == nil {
				return true
			}
			visited[fn.Name] = true
			if v, h := helperCallsStrongSignal(helper.Body, pkgFuncs, visited, depthBudget-1); v {
				verified = true
				hit = h
				return false
			}
		}
		return true
	})
	return verified, hit
}

func filePathHasBrandKeyword(path string) bool {
	lowered := strings.ToLower(path)
	for _, brand := range brandKeywordList {
		if strings.Contains(lowered, brand) {
			return true
		}
	}
	return false
}

func collectFileFuncs(file *ast.File) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name == nil || fn.Recv != nil {
			continue
		}
		out[fn.Name.Name] = fn
	}
	return out
}
