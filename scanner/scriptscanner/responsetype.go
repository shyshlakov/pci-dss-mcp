package scriptscanner

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// jsonMethodNames are framework-specific JSON response method names (Gin, Echo, Fiber).
var jsonMethodNames = map[string]bool{
	"JSON": true, "IndentedJSON": true, "SecureJSON": true,
	"PureJSON": true, "AsciiJSON": true, "JSONP": true,
	"JSONBlob": true, "JSONPretty": true,
}

// htmlMethodNames are framework-specific HTML response method names.
var htmlMethodNames = map[string]bool{
	"HTML": true, "HTMLBlob": true,
}

type responseType int

const (
	responseUnknown responseType = iota
	responseJSON
	responseHTML
)

// detectResponseType inspects a function body for indicators of JSON or HTML response type.
// Used to decide whether CSP headers are required.
//
// JSON indicators: json.NewEncoder, json.Marshal, json.MarshalIndent, "application/json" header.
// HTML indicators: template.Execute, template.ExecuteTemplate, "text/html" header.
// If no indicators found, returns responseUnknown.
func detectResponseType(body *ast.BlockStmt) responseType {
	if body == nil {
		return responseUnknown
	}

	var result responseType
	ast.Inspect(body, func(n ast.Node) bool {
		if result != responseUnknown {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		// Check for selector expressions: pkg.Func() or obj.Method().
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if ident, ok := sel.X.(*ast.Ident); ok {
				// json.NewEncoder, json.Marshal, json.MarshalIndent
				if ident.Name == "json" {
					switch sel.Sel.Name {
					case "NewEncoder", "Marshal", "MarshalIndent":
						result = responseJSON
						return false
					}
				}
				// template.Execute, template.ExecuteTemplate
				if ident.Name == "template" {
					switch sel.Sel.Name {
					case "Execute", "ExecuteTemplate":
						result = responseHTML
						return false
					}
				}
			}

			// Framework-specific JSON response methods (Gin, Echo, Fiber).
			// These are called as receiver.Method() where receiver is typically
			// the context variable (c, ctx, etc.).
			if jsonMethodNames[sel.Sel.Name] {
				result = responseJSON
				return false
			}

			// Framework-specific HTML response methods.
			if htmlMethodNames[sel.Sel.Name] {
				result = responseHTML
				return false
			}

			// Also catch variable.Execute / variable.ExecuteTemplate patterns
			// (e.g., tmpl.Execute(w, data)) -- common in template usage.
			switch sel.Sel.Name {
			case "Execute", "ExecuteTemplate":
				// Could be a template variable. Check if the receiver name
				// hints at template (tmpl, tpl, t, etc.). For safety, we
				// only match "Execute"/"ExecuteTemplate" on identifiers that
				// were already checked above (template.*). Additional heuristic:
				// if the method is called with at least 2 args (writer + data),
				// it's likely a template.
				if len(call.Args) >= 2 {
					if ident, ok := sel.X.(*ast.Ident); ok {
						name := strings.ToLower(ident.Name)
						if strings.Contains(name, "tmpl") || strings.Contains(name, "tpl") ||
							strings.Contains(name, "template") {
							result = responseHTML
							return false
						}
					}
				}
			}
		}

		// Check string literal arguments for Content-Type values.
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				continue
			}
			lower := strings.ToLower(val)
			if strings.Contains(lower, "application/json") {
				result = responseJSON
				return false
			}
			if strings.Contains(lower, "text/html") {
				result = responseHTML
				return false
			}
		}
		return true
	})
	return result
}
