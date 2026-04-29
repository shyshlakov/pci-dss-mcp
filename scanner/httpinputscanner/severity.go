package httpinputscanner

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/shyshlakov/pci-dss-mcp/internal/taint"
	"github.com/shyshlakov/pci-dss-mcp/scanner"
)

// panKeywords promote HTTP-INPUT-LOG severity to HIGH when the field name
// matches. Substring match is case-insensitive on the normalized identifier
// (lowercase, separators stripped).
//
// Notable omission: "bin" - the substring overlaps with neutral tokens like
// "binding", "binary", "sbin"; promotion would produce false positives. The
// fixture contract treats path slot "bin" as MEDIUM.
//
// "apikey" was reclassified to authSecretKeywords - an API key is an auth
// secret, not cardholder data. Related requirement changes from
// [3.3.1, 3.5.1] to [8.6.2].
var panKeywords = []string{
	"pan",
	"primaryaccountnumber",
	"cardnumber",
	"iban",
	"cvv",
	"cvc",
	"securitycode",
	"accountnumber",
}

// authSecretKeywords promote HTTP-INPUT-LOG severity to HIGH when the field
// name signals an authentication secret. Even when the value passed through a
// format-validator sanitizer (uuid.Parse, strconv.Atoi), the field name itself
// signals secret context and the rule fires. PCI DSS requirement is 8.6.2
// (system / application authentication), distinct from PAN/CHD storage
// requirements 3.3.1 / 3.5.1.
//
// Substrings "token" and "auth" are intentionally absent here: they
// false-promote benign path-slot literals like Query("token") and
// Header.Get("Authorization") to HIGH. Specific tokens that are unambiguous
// in source-name positions stay. Sink-side classification (slog/zap/zerolog
// kv keys) is performed separately by classifySinkFieldKeys with the same
// narrowed keyword set.
var authSecretKeywords = []string{
	"apikey",
	"password",
	"secret",
	"bearer",
}

// genericIDKeywords SUPPRESS HTTP-INPUT-LOG entirely. Server-validated
// correlation IDs are recommended observability practice. Adversarial
// mis-naming (an api_key labelled "widget_id") is an accepted false-negative
// trade: source-code access is required to mis-name, downstream review catches
// it, and a future user-override mechanism allows project-specific tightening.
var genericIDKeywords = []string{
	"requestid",
	"traceid",
	"widgetid",
	"tenantid",
	"merchantid",
	"correlationid",
	"spanid",
}

// safeHeaderIdentifiers are HTTP header names whose values are conventionally
// safe to log (correlation IDs, user agent, etc.). When the ONLY tainted
// source feeding a log sink is one of these headers, the scanner suppresses
// the finding to avoid documented false positives. PCI DSS leakage policy
// applies to PAN/SAD/auth secrets - request_id is none of those.
var safeHeaderIdentifiers = map[string]bool{
	"X-Request-ID":     true,
	"X-Request-Id":     true,
	"x-request-id":     true,
	"X-Correlation-ID": true,
	"X-Correlation-Id": true,
	"x-correlation-id": true,
	"X-Trace-ID":       true,
	"X-Trace-Id":       true,
	"x-trace-id":       true,
	"User-Agent":       true,
	"user-agent":       true,
	"Referer":          true,
	"referer":          true,
}

func isSafeIdentifier(identifier string) bool {
	if identifier == "" {
		return false
	}
	if safeHeaderIdentifiers[identifier] {
		return true
	}
	lc := strings.ToLower(identifier)
	switch lc {
	case "x-request-id", "x-correlation-id", "x-trace-id", "user-agent", "referer", "request-id", "trace-id":
		return true
	}
	return false
}

type severityClass int

const (
	severityClassNone severityClass = iota
	severityClassPanCHD
	severityClassAuthSecret
	severityClassGenericID
	severityClassBodySource
)

func classifyKeyword(identifier string) severityClass {
	if identifier == "" {
		return severityClassNone
	}
	norm := normalizeIdentifier(identifier)
	// Generic-ID is checked first because some correlation-ID tokens
	// (e.g. "spanid") substring-overlap PAN tokens ("pan"). Generic-ID
	// keywords are never substrings of PAN or auth-secret keywords, so
	// the reverse precedence cannot regress PAN/auth-secret matches.
	for _, kw := range genericIDKeywords {
		if strings.Contains(norm, kw) {
			return severityClassGenericID
		}
	}
	for _, kw := range panKeywords {
		if strings.Contains(norm, kw) {
			return severityClassPanCHD
		}
	}
	for _, kw := range authSecretKeywords {
		if strings.Contains(norm, kw) {
			return severityClassAuthSecret
		}
	}
	return severityClassNone
}

func normalizeIdentifier(identifier string) string {
	norm := strings.ToLower(identifier)
	norm = strings.ReplaceAll(norm, "_", "")
	norm = strings.ReplaceAll(norm, "-", "")
	return norm
}

// computeSeverity returns the finding severity for a USER_INPUT-tainted
// HTTP-INPUT-LOG sink, plus a shouldEmit flag. shouldEmit=false means the
// finding is SUPPRESSED. Priority order:
//  1. Keyword classes evaluated first: PAN/CHD HIGH, auth-secret HIGH,
//     generic-ID SUPPRESS.
//  2. If no keyword class matched, check the source-chain origin: if the
//     taint flowed from a body-decoder source (request body read, JSON
//     decode, framework body-binding), promote to HIGH regardless of
//     identifier - body content is unknown and may carry PAN/CVV.
//  3. Otherwise fall through to MEDIUM default.
//
// Generic-ID class deliberately wins over the body-source override: a
// validated correlation ID extracted from a decoded body (e.g. struct field
// `WidgetID` after ShouldBindJSON) is observability-safe.
func computeSeverity(ctx UserInputContext) (scanner.Severity, bool) {
	switch classifyKeyword(ctx.Identifier) {
	case severityClassPanCHD, severityClassAuthSecret:
		return scanner.SeverityHigh, true
	case severityClassGenericID:
		return "", false
	}
	if ctx.SourceIsBodyDecoder {
		return scanner.SeverityHigh, true
	}
	return scanner.SeverityMedium, true
}

// computeSeverityWithSink composes source-side keyword classification with
// SINK FIELD KEY classification per Plan 21.1-02 sanitizer-override contract.
// When the source class is severityClassNone but the sink call's slog/zap/
// zerolog kv key matches PAN/CHD or auth-secret class, the sink class is
// applied and severity promotes to HIGH. PAN/CHD wins over auth-secret;
// either beats generic-ID-on-source.
//
// Returns (severity, shouldEmit, effectiveClass). The class drives
// related-requirements selection in fmtSeverityFinding.
//
// Plan 21.1-09 narrowing: the body-source HIGH override is no longer
// triggered solely by ctx.SourceIsBodyDecoder=true. Body content reaching
// a logger without a keyword-class signal lands at MEDIUM. Specific body-
// chain shapes that warrant HIGH (io.Copy reverse-flow into bytes.Buffer
// then String() projection, validator chain into PAN-shaped struct fields)
// surface their promotion via dedicated upstream signals: the BodyBufferChain
// flag set by Plan 21.1-07 reverse-flow seeding, and the validator-chain
// CRITICAL gate added in plan 21.1-09 task 5.
func computeSeverityWithSink(ctx UserInputContext, sinkCall *ast.CallExpr, info *types.Info) (scanner.Severity, bool, severityClass) {
	sourceClass := classifyKeyword(ctx.Identifier)
	if sourceClass == severityClassGenericID {
		return "", false, sourceClass
	}
	chosen := sourceClass
	for _, c := range classifySinkFieldKeys(sinkCall, info) {
		if c == severityClassPanCHD {
			chosen = c
			break
		}
		if c == severityClassAuthSecret && chosen != severityClassPanCHD {
			chosen = c
		}
	}
	switch chosen {
	case severityClassPanCHD, severityClassAuthSecret:
		return scanner.SeverityHigh, true, chosen
	case severityClassGenericID:
		return "", false, chosen
	}
	if ctx.SourceIsBodyDecoder && ctx.BodyBufferChain {
		return scanner.SeverityHigh, true, severityClassBodySource
	}
	return scanner.SeverityMedium, true, severityClassNone
}

// hasOverrideClass reports whether any class in cs would force emission
// regardless of source-side taint state. Used by emit.go to fire the
// sanitizer-override path: when source value was sanitizer-cleared but the
// sink kv key signals secret context, the rule still emits per Plan 03.
func hasOverrideClass(cs []severityClass) bool {
	for _, c := range cs {
		if c == severityClassPanCHD || c == severityClassAuthSecret {
			return true
		}
	}
	return false
}

// classifySinkFieldKeys walks slog / zap / zerolog kv-pair string-literal
// keys at known positions and runs classifyKeyword on each. Returns the set
// of severity classes that signaled secret context. Variable-key positions
// are skipped (SSA territory). Returns nil when call is not a recognized
// kv-bearing sink.
func classifySinkFieldKeys(call *ast.CallExpr, info *types.Info) []severityClass {
	if call == nil {
		return nil
	}
	keys := extractSinkFieldKeyLiterals(call, info)
	if len(keys) == 0 {
		return nil
	}
	var classes []severityClass
	for _, k := range keys {
		if c := classifyKeyword(k); c != severityClassNone {
			classes = append(classes, c)
		}
	}
	return classes
}

// extractSinkFieldKeyLiterals returns string-literal keys at structured
// kv-pair positions for three sink shapes:
//
//  1. slog variadic kv form `slog.Info(msg, k1, v1, ...)` plus the
//     -Context variants - keys at indices 1, 3, 5, ... after kvStartIndex.
//  2. slog/zap attribute builders `slog.String(k, v)` / `zap.Any(k, v)` /
//     `slog.Int(k, v)` etc. - args[0] is the key.
//  3. zerolog event-chain `log.Info().Str(k, v).Msg(t)` - .Str / .Int /
//     .Bool / .Time / .Dur / .Float64 / .Bytes / .Hex / .Base64 take
//     (key, value) on a zerolog.Event receiver.
//
// Recall-biased per feedback_scanner_recall_bias: when the call site is
// ambiguous, even-indexed positional literals are returned conservatively.
// False positives on extracted key names are preferable to silent skips;
// the consumer (classifyKeyword) returns severityClassNone for unknown
// keys so noise is bounded.
func extractSinkFieldKeyLiterals(call *ast.CallExpr, info *types.Info) []string {
	if call == nil {
		return nil
	}
	fn := taint.ResolveCallee(info, call)
	if fn == nil || fn.Pkg() == nil {
		return nil
	}
	pkgPath := fn.Pkg().Path()
	method := fn.Name()
	recv := taint.ReceiverTypeName(fn)

	var out []string

	// Shape 1: slog variadic kv form.
	if pkgPath == "log/slog" || (recv == "Logger" && pkgPath == "log/slog") {
		kvStart := slogKvStartIndex(method)
		if kvStart >= 0 && len(call.Args) > kvStart {
			for i := kvStart; i < len(call.Args); i += 2 {
				if k, ok := stringLitValue(call.Args[i]); ok {
					out = append(out, k)
				}
			}
			return out
		}
	}
	// hclog and logr use the same variadic kv shape on their Logger receiver.
	if (pkgPath == "github.com/hashicorp/go-hclog" && recv == "Logger") ||
		(pkgPath == "github.com/go-logr/logr" && recv == "Logger") ||
		pkgPath == "k8s.io/klog/v2" {
		kvStart := loggerKvStartIndex(pkgPath, method)
		if kvStart >= 0 && len(call.Args) > kvStart {
			for i := kvStart; i < len(call.Args); i += 2 {
				if k, ok := stringLitValue(call.Args[i]); ok {
					out = append(out, k)
				}
			}
			return out
		}
	}

	// Shape 2: slog / zap attribute builders - first arg is the key.
	if isAttrBuilderKvShape(pkgPath, method) {
		if len(call.Args) >= 1 {
			if k, ok := stringLitValue(call.Args[0]); ok {
				out = append(out, k)
			}
		}
		return out
	}

	// Shape 3: zerolog Event chain - .Str/.Int/.Bool/etc. (key, value).
	if pkgPath == "github.com/rs/zerolog" && recv == "Event" {
		if isZerologKvMethod(method) && len(call.Args) >= 1 {
			if k, ok := stringLitValue(call.Args[0]); ok {
				out = append(out, k)
			}
		}
		return out
	}

	return out
}

// slogKvStartIndex returns the index of the first kv-pair argument for a
// slog top-level function or *Logger method. Returns -1 when the method is
// not a kv-bearing entry point.
func slogKvStartIndex(method string) int {
	switch method {
	case "Info", "Warn", "Error", "Debug":
		return 1
	case "InfoContext", "WarnContext", "ErrorContext", "DebugContext":
		return 2
	case "Log":
		return 3
	case "LogAttrs":
		return 3
	}
	return -1
}

// loggerKvStartIndex covers logr / hclog / klog kv-bearing call shapes.
func loggerKvStartIndex(pkgPath, method string) int {
	switch pkgPath {
	case "github.com/go-logr/logr":
		switch method {
		case "Info":
			return 1
		case "Error":
			return 2
		}
	case "github.com/hashicorp/go-hclog":
		switch method {
		case "Info", "Warn", "Error", "Debug", "Trace":
			return 1
		}
	case "k8s.io/klog/v2":
		switch method {
		case "InfoS":
			return 1
		case "ErrorS":
			return 2
		}
	}
	return -1
}

// isAttrBuilderKvShape reports whether pkgPath.method takes (key, value)
// as its first two args (slog.String / slog.Any / zap.Int / etc.).
func isAttrBuilderKvShape(pkgPath, method string) bool {
	switch pkgPath {
	case "log/slog":
		switch method {
		case "String", "Any", "Int", "Int64", "Uint64", "Bool", "Float64", "Duration", "Time", "Group":
			return true
		}
	case "go.uber.org/zap":
		switch method {
		case "String", "Any", "Int", "Int64", "Uint64", "Bool", "Float64", "Duration", "Time", "Error", "Stringer":
			return true
		}
	}
	return false
}

// isZerologKvMethod reports whether method on zerolog.Event takes
// (key, value) as its first two args.
func isZerologKvMethod(method string) bool {
	switch method {
	case "Str", "Int", "Int64", "Uint64", "Bool", "Time", "Dur", "Float64", "Err", "Bytes", "Hex", "Base64", "Stringer", "Any", "Interface":
		return true
	}
	return false
}

// stringLitValue extracts the unquoted Go string value of a *ast.BasicLit
// of kind STRING. Returns ("", false) for non-string-literal expressions.
func stringLitValue(expr ast.Expr) (string, bool) {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v := bl.Value
	if len(v) >= 2 && (v[0] == '"' || v[0] == '`') {
		v = v[1 : len(v)-1]
	}
	return v, true
}

func matchesPanKeyword(identifier string) bool {
	return classifyKeyword(identifier) == severityClassPanCHD
}

// relatedRequirementsForLog dispatches by keyword class. The body-source
// override has no canonical related-reqs because body content shape is
// unknown.
func relatedRequirementsForLog(severity scanner.Severity, ctx UserInputContext) []string {
	if severity != scanner.SeverityHigh {
		return nil
	}
	switch classifyKeyword(ctx.Identifier) {
	case severityClassPanCHD:
		return []string{"3.3.1", "3.5.1"}
	case severityClassAuthSecret:
		return []string{"8.6.2"}
	}
	return nil
}

// relatedRequirementsForLogClass dispatches related-reqs by the effective
// keyword class chosen via computeSeverityWithSink. Used by emit.go so
// sanitizer-override findings (where ctx.Identifier is empty but the sink
// key drives the class) still surface the correct related-reqs.
func relatedRequirementsForLogClass(class severityClass) []string {
	switch class {
	case severityClassPanCHD:
		return []string{"3.3.1", "3.5.1"}
	case severityClassAuthSecret:
		return []string{"8.6.2"}
	case severityClassBodySource:
		return []string{"3.3.1", "6.2.4"}
	}
	return nil
}
