# HTTP Input Taint Tracking

pci-dss-mcp tracks raw HTTP framework input (path params, query strings,
headers, decoded request bodies) as it flows into log, error, and panic sinks.
When such input reaches a sink without first passing through a sanitizer
barrier, the scanner emits one of three rule IDs that map directly to PCI DSS
v4.0.1 requirements 6.2.4 and 10.2.1.

## Overview

Real Go payment services do not log known PAN values directly. The leak vector
is upstream: a request enters a handler, the handler reads a value via
`c.Param("bin")` or `c.GetHeader("X-Apikey")`, and the value flows through
helpers, error wrappers, and structured loggers before landing in an audit log.
A static reader of the handler cannot prove the value is not a PAN, an Authorization
bearer, a CVV, or any other piece of cardholder data. Logging it is a violation
of the global rule "never log raw external input by default."

The HTTP-INPUT taint rule family exists to detect that exact flow. The
detection is recall-biased per memory `feedback_scanner_recall_bias`: when the
scanner cannot prove a value is sanitized, it emits a finding. False positives
are triaged via the AI classifier (`triage_findings`); false negatives ship
silently to production.

The three rules map to:
- `HTTP-INPUT-LOG` -> PCI DSS 10.2.1 (audit log content). Related to 3.3.1 and
  3.5.1 when the source identifier name matches a PAN keyword.
- `HTTP-INPUT-ERROR` -> PCI DSS 6.2.4 (error responses leaking sensitive
  context).
- `HTTP-INPUT-PANIC` -> PCI DSS 10.2.1 (recovery middleware logs panic value).
  Related to 6.2.4.

## How it works

The scanner runs four passes against every Go file matching its include set:

1. **Source pass.** Tag every value originating from a recognized HTTP
   framework accessor (path / query / header / body decoder) with a `USER_INPUT`
   taint kind. Body-decoded structs are tagged at the field-read level so that
   any subsequent `req.Field` access carries the taint.
2. **Propagation pass.** Walk every assignment, function call, and return
   statement; propagate taint through `fmt.Sprintf` family, `fmt.Errorf %w`,
   `errors.Wrap`, multi-error appenders, string concatenation, type
   conversions, `context.WithValue`, and the `recover()` -> panic-source
   inheritance chain.
3. **Sanitizer pass.** When a tainted value passes through a recognized masker
   (public `mask.*` / `card.Maskify` package, method-on-struct `(*Bundle).Mask`,
   function-shape `Mask` or `Maskify` by signature, or a regex-redact
   heuristic), clear the taint on the returned value. Sanitization is
   branch-aware: a mask call inside `if err == nil { ... }` does NOT clear the
   taint on the error branch.
4. **Sink pass.** When a still-tainted value reaches a recognized log / error /
   panic sink (or a custom helper that wraps such a sink per D-14
   indirection), emit a finding with the appropriate rule ID and severity.

The engine is intra-procedural by default and reaches into one-hop callee
parameters via the D-14 custom-helper indirection rules. Cross-procedural
recall beyond one hop is the territory of the Phase 21 Track B SSA proof of
concept.

## Source models

Recognized as `USER_INPUT` taint sources, by framework tier.

### Tier 1 frameworks (shipped in v0.7)

| Framework | Sources covered |
| --- | --- |
| gin (`github.com/gin-gonic/gin`) | `(*gin.Context).Param`, `Query`, `DefaultQuery`, `GetHeader`, `GetRawData`, `Request.URL.Path`, `Request.URL.RawQuery`, `Request.Header.Get`, `ShouldBind*` family (JSON, XML, YAML, TOML, MsgPack, ProtoBuf, Header, Query, Uri) |
| chi (`github.com/go-chi/chi/v5`) | `chi.URLParam(r, name)`, plus stdlib `r.URL.Query().Get` and `r.Header.Get` since chi reuses net/http accessors |
| gorilla/mux | `mux.Vars(r)[name]`, plus stdlib accessors |
| net/http (Go 1.22+) | `(*http.Request).PathValue`, `URL.Path`, `URL.RawQuery`, `Header.Get`, `Form` / `PostForm` / `MultipartForm` after parsing |
| echo v4 (`github.com/labstack/echo/v4`) | `c.Param`, `c.QueryParam`, `c.Request().Header.Get`, struct-tag binders |
| fiber v2 (`github.com/gofiber/fiber/v2`) | `c.Params`, `c.Query`, `c.Get`, `c.BodyParser` |
| validator (`github.com/go-playground/validator/v10`) | `validator.FieldError.Value()` exposes the user-supplied value on validation failures |

### Body decoders

Beyond JSON, the scanner recognizes the following decoder families. In every
case, the populated struct's fields become tainted after decode, and any later
field read carries the taint:

JSON, XML, YAML, TOML, MsgPack, Protobuf, CBOR, Form (urlencoded), Header
binding, Query binding, URI binding.

### Tier 2 frameworks (deferred to v0.8 follow-up release)

`kratos v2`, `apex/log`, `charmbracelet/log`. Their accessor / sink shapes
overlap entirely with Tier 1; the deferral is about test coverage, not
architectural reach.

### Tier 3 (user-configurable via Phase 25 YAML)

`fasthttp`, `beego`, `iris`, `httprouter`, `phuslu/log`, and any
project-internal framework. These rely on the Phase 25 Custom YAML Rule Engine
once shipped. Until then, project teams using Tier 3 frameworks see no
HTTP-INPUT-* findings. This is documented as a known scope boundary, not a
silent gap.

### Negative differentiators (route templates do NOT taint)

Route-template accessors return compile-time-fixed strings, not user input.
The scanner explicitly recognizes them and does NOT emit findings:

- gin `c.FullPath()`
- echo `c.Path()`
- chi `chi.RouteContext(r.Context()).RoutePattern()`
- gorilla/mux `mux.CurrentRoute(r).GetPathTemplate()`
- fiber `c.Route().Path`
- iris `ctx.GetCurrentRoute().Tmpl()`

Mislabeling a route template as a taint source is a frequent root-cause of
false positives. The fixture file
`testdata/vulnerable-payment-service/internal/http_input/route_template_no_taint.go`
exercises this differentiator.

## Propagator rules

Tainted values flow through the following constructs unchanged unless they
pass through a sanitizer barrier.

| Construct | Behavior |
| --- | --- |
| `fmt.Sprintf`, `fmt.Sprint`, `fmt.Sprintln` | output inherits taint of any argument |
| `fmt.Errorf("...%w", taintedErr)` | returned error inherits taint |
| `errors.Wrap`, `errors.Wrapf`, `errors.WithMessage` (pkg/errors) | wrapped error inherits taint |
| `errors.Join(errs...)` (Go 1.20+) | joined error inherits taint of any input |
| `multierror.Append`, `multierr.Append`, `multierr.Combine` | combined error inherits taint of any input |
| `cockroachdb/errors.Wrap`, `Wrapf`, `WithMessage`, `WithSafeDetails` | wrapped error inherits taint |
| `eris.Wrap`, `eris.Wrapf` | wrapped error inherits taint |
| string concatenation `taint + s`, `s + taint`, `strings.Join` | output inherits taint |
| type conversion `string(taintedBytes)`, `[]byte(taintedString)` | result inherits taint |
| `context.WithValue(ctx, key, taint)` | context inherits taint at key |
| `gin.Context.Set(key, taint)` -> `gin.Context.GetString(key)` | round-trip carries taint |
| `recover()` inside a `defer` | inherits taint from the matching `panic(...)` site |

### Out-of-scope propagators

Goroutine boundaries (`go fn(taint)`) and channel sends/receives
(`ch <- taint`, `<-ch`) are not modeled by the AST engine. The Track B SSA
proof of concept measures whether these warrant a future migration. Track A
ships without them; missed cross-goroutine flows are documented as a known
recall pocket.

## Sink models

Recognized log, error, and panic sinks. When a tainted value reaches one of
these (with no sanitizer in between), a finding is emitted.

### LOG sinks (rule HTTP-INPUT-LOG)

| Library | Recognition | Tier |
| --- | --- | --- |
| `log/slog` | `slog.Info`, `Warn`, `Error`, `Debug`, `*Context` variants, `slog.With`, `slog.Group`, attribute builders (`slog.String`, `slog.Any`, etc.) | 1 |
| `sirupsen/logrus` | `WithField`, `WithFields(logrus.Fields{})`, `WithFields(map[string]any{})`, `WithFields(map[string]interface{}{})`, `Info`, `Error`, etc. | 1 |
| `uber-go/zap` | `Logger.Info`, `Error`, etc.; field builders `zap.String`, `zap.Any`; `Sugar().Infow` slog-style positional kv | 1 |
| `rs/zerolog` | Event chain: `Info().Str(k, v)`, `Int(k, v)`, `Bool(k, v)`, `Err(err)`, `Any(k, v)`, `Interface(k, v)`, finalized by `.Msg`, `.Msgf`, `.Send` | 1 |
| `go-logr/logr` | positional kv `Info(msg, kvs...)`, `WithValues(kvs...)` | 1 |
| `k8s.io/klog/v2` | structured `InfoS(msg, "k", v, ...)`, `ErrorS`; format-string `Infof("%v", taint)` flows through the `fmt.Sprintf` propagator | 1 |
| `hashicorp/go-hclog` | positional kv `Info(msg, kvs...)`, `With(kvs...)` | 1 |
| `apex/log` | `WithField`, `WithFields(Fielder)`, `Info`, `Error` | 2 (v0.8) |
| `charmbracelet/log` | slog-style positional kv plus the slog-handler bridge | 2 (v0.8) |

The recognition heuristic is signature-shape-based: a method receiver that
resolves to one of the logger types above plus tainted positional kv pairs
(or chain-builder arguments) is enough. The engine does not require a hardcoded
package path.

A struct field whose declared type is a logger (for example
`type H struct{ log *slog.Logger }`) is recognized as a logger receiver. Calls
to `h.log.Info(...)` carry the same sink semantics as direct `slog.Info(...)`
calls.

### ERROR sinks (rule HTTP-INPUT-ERROR)

| Sink shape | Example |
| --- | --- |
| `fmt.Errorf("...%w", taintedErr)` whose error is later returned and logged via `err.Error()` chain or surfaced to the client | `return fmt.Errorf("path %s not found: %w", c.Param("id"), inner)` |
| `errors.New(taintedString)` | `errors.New(c.GetHeader("X-Apikey"))` |
| `(*http.ResponseWriter).Write([]byte(taint))` | `w.Write([]byte(c.Param("bin")))` |
| `fmt.Fprintf(w, "...%s...", taint)` writing raw input back to the client | `fmt.Fprintf(w, "invalid: %s", r.URL.Path)` |
| Centralized abort helper recognized via D-14 indirection | `httperr.Abort(c, fmt.Errorf("bad %s", c.Param("id")))` |

### PANIC sinks (rule HTTP-INPUT-PANIC)

| Sink shape | Example |
| --- | --- |
| Direct `panic(tainted)` | `panic(c.Param("bin"))` |
| `(*log).Panic` family | `log.Panicf("got %s", c.GetHeader("X"))` |
| `defer func(){ if r := recover(); r != nil { slog.Error(..., "value", r, ...) } }()` re-log | the `recover()` value inherits taint from a tainted panic site in the same package |
| Framework recovery middleware (`gin.Recovery()`, `chi.Recoverer`, `mux.PanicHandler`, echo `Recover()`, fiber recovery) plus a tainted panic site in the same wired path | conservative emission per memory `feedback_scanner_recall_bias` |

## Sanitizer barriers

When a tainted value passes through a recognized masker, the returned value is
no longer tainted. The following shapes are recognized:

| Shape | Recognition |
| --- | --- |
| Public `mask.*` package | calls into `mask.NewBundle(...).Mask(...)` and same-shaped helpers |
| `card.Maskify` family | direct package-name match |
| Method-on-struct masker | any `(*X).Mask(taint) []byte` method whose package surface contains regex / redact patterns; covers per-handler / per-middleware Bundle struct fields like `m.masker.Mask(...)` |
| Function-shape masker | top-level `Mask(b []byte) []byte` or `Maskify(s string) string` recognized by signature |
| Regex redact heuristic | `regexp.*ReplaceAll*` whose pattern literal contains a redact-shaped expression |
| Wrapped HTTP client | `interaction.NewClientTransport(http.Client, mask.NewBundle(...))` style outbound wraps are treated as sanitized at the transport level |

### Branch-aware analysis

Sanitization is per-branch. Consider:

```go
if err := decode(c, &req); err == nil {
    slog.Info("ok", slog.String("v", Maskify(req.Bin)))
} else {
    slog.Error("decode failed", slog.String("raw", req.Bin))
}
```

The success branch masks the value; the error branch logs it raw. The scanner
emits a finding for the error branch only. The fixture
`testdata/vulnerable-payment-service/internal/http_input/mask_bypass_err_path.go`
exercises this case.

### Project-specific maskers

Real services use a per-handler / per-middleware Bundle struct
(`m.masker.Mask(...)`, `c.masker.Mask(...)`) where the `*Bundle` type lives in
a project-internal package. The shape is universal but the package path varies
per project. Track A recognizes the public-shape patterns above. Project-
internal mask packages are user-configurable via Phase 25 YAML once shipped.

If your project wraps masking in a custom package, declare it via
`.pci-mcp/rules/*.yaml` taint sanitizer entries (Phase 25). Until Phase 25
ships, suppress per-finding via `// pci-ignore: <reason>` inline comments.

## Custom-helper indirection

Real Go services centralize log emission and error reporting through helper
functions. The scanner recognizes two indirection shapes as if the wrapped
sink emitted directly.

### Centralized abort helpers

A function in any package that takes an `error` parameter AND whose body
contains a `slog`, `logrus`, `zap`, or `log.Print*` call is treated as a sink
for HTTP-INPUT-ERROR. Examples:

```go
httperr.Abort(c *gin.Context, err error)        // recognized
respondError(c *gin.Context, err error)         // recognized
JSONError(w http.ResponseWriter, err error, code int)  // recognized
```

The fixture file
`testdata/vulnerable-payment-service/internal/http_input/central_abort_log.go`
exercises this pattern.

### Context-extracted loggers

A function that takes `context.Context` and returns a logger-shaped value is
treated as the logger source for downstream `.Info` / `.Error` calls. Examples:

```go
CtxLog(ctx context.Context) *slog.Logger           // recognized
LoggerFrom(ctx context.Context) logr.Logger        // recognized
zerolog.log.Ctx(ctx context.Context) *zerolog.Logger  // recognized
```

Tainted values that flow through `slog.With(taint, ...)` and into the context
via `context.WithValue(ctx, key, logger)` are detected through the context
propagator.

Where AST recall is insufficient (helper defined in a renamed package, helper
that wraps another helper transitively), the Track B SSA proof of concept
measures the cross-procedural recall delta and informs a future engine
migration decision.

## Three new rule IDs

| Rule | Source -> Sink | Default | PCI DSS |
| --- | --- | --- | --- |
| `HTTP-INPUT-LOG` | framework input -> log sink, no sanitizer | MEDIUM (HIGH on PAN keyword) | 10.2.1 (related 3.3.1, 3.5.1) |
| `HTTP-INPUT-ERROR` | framework input -> `fmt.Errorf` or response writer write-back | MEDIUM | 6.2.4 |
| `HTTP-INPUT-PANIC` | framework input -> `panic(...)` or `defer recover()` re-log | MEDIUM | 10.2.1 (related 6.2.4) |

All three rules are taint-engine-only. When `include_taint=false`, the scanner
emits a single INFO `HTTP-INPUT-TAINT-OFF` finding so users understand why no
HTTP-input rule fired.

## Severity policy

MEDIUM by default. Severity escalates to HIGH when the source identifier name
matches a PAN keyword (`bin`, `card`, `pan`, `account`, `iban`, `cvv`, `pin`,
`apikey`).

The policy is recall-biased per memory `feedback_scanner_recall_bias`: when in
doubt, emit. The asymmetric compliance cost (a missed PAN log line is a
findable PCI DSS violation; a triaged false positive is a one-second AI
classification) justifies the bias. The fixture file
`testdata/vulnerable-payment-service/internal/http_input/route_pan_promotion.go`
exercises the PAN-keyword promotion path.

## TriageHint tags

The AI triage step (`triage_findings`) groups HTTP-INPUT findings under three
TriageHint tags:

- `http-input-leak` for HTTP-INPUT-LOG findings
- `framework-input-error` for HTTP-INPUT-ERROR findings
- `recovery-leak` for HTTP-INPUT-PANIC findings

These taxonomy slots drive AI clustering and user-facing summaries.

## Examples

### Positive case 1: gin path param logged raw

```go
func LogPathParam(c *gin.Context) {
    slog.Info("lookup",
        slog.String("bin", c.Param("bin")),
    )
}
```

Source: `c.Param("bin")` is a USER_INPUT taint source. Sink: `slog.Info` via
`slog.String`. No sanitizer in the flow. Emits HTTP-INPUT-LOG MEDIUM by
default; promoted to HIGH because the source identifier name `bin` matches a
PAN keyword.

### Positive case 2: PAN-keyword promotion

```go
func LogPAN(c *gin.Context) {
    slog.Info("debit", slog.String("pan", c.Param("pan")))
}
```

Source identifier `pan` matches a PAN keyword; severity escalates to HIGH and
related requirements 3.3.1 / 3.5.1 are added to the finding.

### Negative case 1: route template

```go
func LogRouteTemplate(c *gin.Context) {
    slog.Info("matched route",
        slog.String("route", c.FullPath()),
    )
}
```

`c.FullPath()` returns the compile-time route template, not user input.
Recognized as a negative differentiator. Zero findings emitted.

### Negative case 2: sanitizer barrier

```go
func LogPathParamMasked(c *gin.Context) {
    raw := c.Param("bin")
    slog.Info("lookup",
        slog.String("bin", Maskify(raw)),
    )
}
```

`Maskify` clears the taint on the returned value. Zero findings emitted.

### Real-world exemplar: Hashicorp Vault sys_health.go

The Hashicorp Vault `http/sys_health.go` handler reads request fields but logs
only own-derived state (error code, internal IDs) and never the raw URL path,
headers, or body. It serves as a positive example of correct behavior. Per
the universality research, none of the 10 surveyed open-source Go services
that DO log raw input is a payment processor; Vault demonstrates the
production discipline expected of a fintech codebase.

## Severity-aware emission (Phase 21.1)

HTTP-INPUT-LOG severity is determined by the source identifier name (slog field
name, struct field name, or path slot name) and, for sink-side classification,
the kv-pair key literal at the sink call. The taxonomy has four classes:

| Class | Keywords (substring match, case-insensitive, separators stripped) | Severity | Related PCI DSS |
|-------|--------------------------------------------------------------------|----------|-----------------|
| PAN/CHD | pan, primaryaccountnumber, cardnumber, iban, cvv, cvc, securitycode, accountnumber | HIGH | 3.3.1, 3.5.1 |
| Auth secret | apikey, token, password, secret, bearer, auth | HIGH | 8.6.2 |
| Generic ID | requestid, traceid, widgetid, tenantid, merchantid, correlationid, spanid | suppressed | n/a |
| Other (body / header / unknown) | none of the above | MEDIUM | n/a |

Generic-ID class suppresses HTTP-INPUT-LOG entirely. Server-validated
correlation IDs are recommended observability practice. Attacker-controlled
mis-naming (an api_key labelled `widget_id`) is acknowledged as an accepted
false-negative trade per scanner recall-bias policy. The AI triage layer
catches downstream review and Phase 25 YAML rules allow user override.

Severity-aware emission applies to HTTP-INPUT-LOG only. HTTP-INPUT-ERROR and
HTTP-INPUT-PANIC retain the Phase 21 default severity (MEDIUM unless PAN
keyword promotes to HIGH). HTTP-INPUT-ERROR additionally promotes to HIGH +
[8.6.2] when the error argument's Stringer-typed receiver type name matches
the auth-secret keyword set ({token, authorization, auth}); the receiver type
name is a stronger signal than path-slot literals because the developer chose
to model auth-secret data as a typed struct.

### CRITICAL severity tier (Phase 21.1)

A new CRITICAL tier fires when the HTTP-INPUT-LOG sink directly receives a
`validator.FieldError.Value()` invocation AND the bound struct (the JSON
target of an upstream `c.ShouldBindJSON(&r)` or `Decoder.Decode(&r)`) has at
least one field whose `validate` or `json` tag matches a PAN/CHD keyword.
This is the PAN-validation profile: when a payment-shape struct fails
validation, the validator framework exposes the user-supplied field value
through `FieldError.Value()`, and logging it at the validation-failure site
leaks PAN. Related-reqs profile is `[3.4.1, 8.6.2]`. The direct-arg gate
distinguishes high-confidence single-hop chains from indirect chains (e.g.
map hop) which fall back to MEDIUM.

The PAN-validation profile is detected by an `Identifier="pan-validator"`
label on the source spec. Triage payloads consume this label to surface the
profile in the AI clustering output.

### Sink-side keyword classification (Phase 21.1)

Beyond source-identifier matching, the engine also classifies the kv-pair
key literal at the sink call site. The slog variadic shape
`slog.Info(msg, "api_key", val)`, the slog/zap attribute-builder shape
`slog.String("api_key", val)`, and the zerolog Event-chain shape
`Info().Str("api_key", val).Msg(...)` all surface a string-literal key at a
known argument position. When that literal matches the auth-secret or
PAN/CHD keyword set, the sink-side classification overrides the source-side
sanitizer-clear path (a uuid.Parse-cleared value still fires HIGH if the
sink key signals auth-secret context). Variable-key positions
(`slog.Info(msg, k1, val)` where `k1` is a non-literal) are skipped per
recall-bias policy; SSA territory.

## Format-validator sanitizers (Phase 21.1)

Stdlib parsers that constrain output to a known format physically incapable
of carrying PAN / CVV / auth-secret content. On the success branch
(`if err == nil { use(parsed) }`), the parsed value is no longer
USER_INPUT-tainted.

| Function | Output constraint |
|----------|-------------------|
| `uuid.Parse` / `MustParse` / `ParseBytes` (google/uuid) | UUID v1-v7 hex |
| `uuid.FromString` / `FromBytes` / `(*UUID).Parse` (gofrs/uuid) | UUID v1-v7 hex |
| `time.Parse` / `ParseInLocation` / `ParseDuration` | RFC 3339 / configured layout |
| `strconv.Atoi` / `ParseInt` / `ParseUint` / `ParseFloat` / `ParseBool` | Numeric / bool |
| `net.ParseIP` / `ParseCIDR` | IPv4 / IPv6 |
| `net/netip.ParseAddr` / `ParseAddrPort` / `ParsePrefix` | IP address |
| `net/mail.ParseAddress` / `ParseAddressList` | RFC 5322 mail-shaped |

`net/url.Parse` and `ParseRequestURI` are NOT modeled as sanitizers. The
engine has no per-field taint state, so a whole-value sanitizer would
falsely clear `URL.RawQuery` / `Fragment` taint (a real leak vector).
Existing field-read sources for `URL.Path` / `RawQuery` / `RawPath` give
correct partial-sanitizer semantics naturally.

Auth-secret keyword override: when the downstream sink's source identifier
or sink-key literal matches the auth-secret class (apikey / token / etc.),
the sanitizer is BYPASSED and the rule fires HIGH. Format constraint does
not prevent the value from BEING the secret; the field name signals the
sensitive context regardless.

## gin recovery middleware as USER_INPUT auxiliary source (Phase 21.1)

The `recovered any` callback parameter (index 1) of these gin middleware
constructors is recognized as a USER_INPUT taint source:

- `gin.CustomRecoveryWithWriter(io.Writer, func(c *Context, recovered any))`
- `gin.CustomRecovery(func(c, recovered any))`
- `gin.RecoveryWithWriter(io.Writer, ...func(c, recovered any))` (variadic, all callbacks)

Bare panic dedup: when a file installs a gin recovery callback sink, bare
`panic(taint)` emissions in the same file are suppressed. The callback
PANIC finding is the canonical sink for the family, mirroring the existing
`defer recover()` dedup precedent.

Limitation: identifier-passed callbacks (`gin.CustomRecovery(myRecoveryFn)`
where `myRecoveryFn` is a named function declared elsewhere) are NOT
modeled. Only `*ast.FuncLit` callbacks are recognized at the source site.
Inter-procedural propagation is deferred to Phase 26 SSA.

Echo and fiber recovery middleware are Tier 2 (deferred to v0.8 follow-up).
chi.Recoverer uses bare `recover()` and is already covered by Phase 21 V2
D-13 propagators.

The error sink catalog also recognizes `(*gin.Context).AbortWithError` as
an HTTP-INPUT-ERROR sink alongside `c.AbortWithStatusJSON` and the
centralized abort helpers.

## Method-projector propagators (Phase 21.1)

Method calls whose receiver state carries USER_INPUT taint propagate it to
the result:

- `(*bytes.Buffer).String() string` and `.Bytes() []byte`
- `(*strings.Builder).String() string`
- Reverse-flow: `(*bytes.Buffer).WriteString(s)` / `.Write(p)` taint the receiver when `s` / `p` are tainted; same for `(*strings.Builder)`

`(*url.URL).String()` is NOT modeled (per-field state required, deferred).
Custom user types implementing `Stringer` are NOT auto-recognized; Phase 25
YAML user override is the path for project-specific recognition.

## Format-verb-aware fmt analysis (Phase 21.1)

`fmt.Errorf` and `fmt.Sprintf` with a literal format string containing
`%s` / `%v` / `%w` invoke `Stringer.String()` semantics on Stringer-typed
args at format time. When the Stringer's receiver carries USER_INPUT taint,
the formatted result inherits taint.

- Verbs that DO invoke Stringer: `%s`, `%v`, `%w`
- Verbs that DO NOT: `%d`, `%x`, `%o`, `%q`, `%b`, `%t`, `%c`, `%U`, `%f`, `%g`, `%e`
- Variable format strings (non-literal first arg) fall back to existing uniform passthrough; SSA territory.
- Width / precision / flag modifiers are tolerated (`%+v`, `%-10s`, `%5.2f`).

## io.Copy ReverseFlow propagation (Phase 21.1)

`io.Copy(dst, src)` and friends propagate taint in REVERSE: when `src` is
USER_INPUT-tainted, the underlying object referenced by `dst` becomes
tainted. Covers:

- `io.Copy(&buf, taintedReader)` taints buf
- `io.CopyN`, `io.CopyBuffer`, `io.WriteString` follow the same shape

Combined with the method-projector forward propagator above:
`io.Copy(&buf, c.Request.Body)` ReverseFlow taints `buf`, then
`buf.String()` forward-propagates the taint into a slog sink.

The reverse-flow seeding sets a `BodyBufferChain` context flag that the
severity-aware emission consumes: a body-source HIGH severity override now
requires BOTH `SourceIsBodyDecoder=true` AND `BodyBufferChain=true`. Plain
body-field reads through stdlib helpers (such as `io.ReadAll`) settle to
MEDIUM; only the buffer/builder reverse-flow chain triggers HIGH with a
related-reqs profile of `[3.3.1, 6.2.4]`.

Limitation: only `&ident` and bare-`ident` dst shapes are modeled.
Composite literals and function returns are SSA territory.

## Suppression

- **Inline:** add `// pci-ignore: <reason>` on the line above the offending
  call. The finding is emitted as `SUPPRESSED` with the reason text in the
  audit trail (auditors see what was suppressed).
- **`.pci-mcp-ignore` file:** declare rule pattern entries to suppress
  HTTP-INPUT-* findings across paths or rule IDs.
- **Phase 25 YAML (when shipped):** declarative custom rules let project
  teams add their own framework / logger / sanitizer / sink shapes without a
  pci-dss-mcp release.

## Out of scope

- **gRPC handlers.** gRPC has a fundamentally different shape (`*pb.Request`
  field accessors, interceptor-based logging via the
  `grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging/payload`
  interceptor). Phase 21.2 (separate phase) tracks gRPC scope; it will reuse
  the `USER_INPUT` taint kind verbatim and add a parallel `GRPC-INPUT-*` rule
  family.
- **Cross-service taint flow.** Phase 24 (Cross-Service CHD Flow Mapping)
  tracks taint that crosses the network boundary between two services.
- **Project-internal frameworks, loggers, and error wrappers.** Phase 25
  Custom YAML Rule Engine territory.
- **Goroutine and channel boundaries.** Track B SSA proof of concept measures
  whether to add these in a future engine version.
- **Runtime / dynamic analysis.** Always out of scope per
  `research/FEATURES.md` AF-1.

## See also

- [docs/taint.md](taint.md) -- PAN/CVV/SAD taint engine
- [docs/scan_pan_data.md](scan_pan_data.md) -- PAN-specific rules
- [docs/severity.md](severity.md) -- severity policy
- [docs/requirement-mapping.md](requirement-mapping.md) -- rule_id to PCI DSS
  requirement mapping
- [docs/pci-coverage.md](pci-coverage.md) -- PCI DSS v4.0.1 coverage matrix
