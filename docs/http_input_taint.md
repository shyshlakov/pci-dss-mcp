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
