# Tools Reference

pci-dss-mcp provides **14 MCP tools**: 10 scanners, 1 report orchestrator,
1 triage engine, 1 vulnerability database updater, and 1 requirement
lookup.

All tools declare a typed `OutputSchema` auto-inferred from Go struct
`jsonschema` tags (MCP spec 2025-06-18 compliance). Clients receive
both a 1-line `content.text` summary AND a validated `structuredContent`
payload on every call.

## v0.2.0 migration note (breaking)

As of **v0.2.0**, the default response shape of `generate_compliance_report`
changed from a flat `findings: [...]` array to a summary-first variant
tagged `response_shape: "summary"`. The three tools
`generate_compliance_report`, `triage_findings`, and `scan_pan_data`
now accept an optional `cursor` input parameter for paginated follow-ups.

**To restore the pre-v0.2.0 shape on the next call**, pass `limit: -1` to
`generate_compliance_report`. The server returns a flat findings array
(capped at 500 entries; over-cap responses surface
`pagination.auto_capped: true` with `total_before_cap` / `kept` hints).

**To drill into the full findings list progressively**, follow the
`pagination.next_cursor` returned in the default summary response. Each
follow-up call returns 60 findings per page (`FlatResponse`) plus a new
cursor when more pages remain. Cursors are tool-scoped — a cursor issued
by `generate_compliance_report` cannot be replayed against `triage_findings`
(the server returns `CURSOR_MALFORMED`). Session cache TTL is 10 minutes;
expired cursors return `CURSOR_EXPIRED` and the client re-runs without a
cursor to start a fresh scan.

## generate_compliance_report

Run all PCI DSS v4.0.1 compliance scanners and generate a comprehensive report.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to the project directory to scan |
| `dep_scan_mode` | string | no | Dependency scanner mode: `auto` (default), `online`, `offline` |
| `include_tests` | bool | no | Include `_test.go` files in scan results. Default `false` (industry SAST consensus) |
| `include_taint` | bool | no | flow-based severity adjustment via `go/packages`. **Default `true`** (production precision, as of ). Set `false` for fast dev iteration (adds 5-30s otherwise). Requires `go` binary on `PATH`; falls back to AST-only on failure |
| `min_severity` | string | no | Scope the response to findings at or above this severity. One of `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` (case-insensitive). Default: no filter |
| `rule_filter` | string | no | Comma-separated list of rule IDs (`PAN-KEYWORD,PAN-TYPE`) OR a single regex between slashes (`/PAN-.*/`). Default: no filter |
| `limit` | int | no | Maximum number of findings to return after filtering. Default `0` (summary-first). Pass `-1` to request the legacy flat findings array (auto-capped at 500) |
| `cursor` | string | no | Opaque pagination cursor. Empty = fresh scan. Non-empty = resume from session cache (10-minute TTL) |

All four filter/scope parameters (..) apply **before**
serialization, so they genuinely shrink the response size rather than
just hiding content client-side.

**Pagination and cursor (v0.2.0+):**

The response is one of three variants, tagged by `response_shape`:

- `response_shape: "summary"` — default, returned when no filter/cursor is
  present. Carries severity totals, per-requirement statuses, up to 10 top
  findings per severity (CRITICAL / HIGH / MEDIUM), and
  `pagination.next_cursor` for follow-up.
- `response_shape: "flat"` — returned on cursor follow-up OR when any of
  `min_severity` / `rule_filter` / positive `limit` is set. Up to 60
  findings per page, plus `next_cursor` when more pages remain.
- `response_shape: "error"` — `CURSOR_EXPIRED` (10-min TTL lapsed) or
  `CURSOR_MALFORMED` (decode failure / cross-tool replay). Client retries
  without a cursor.

**Legacy flat response:** pass `limit: -1` to restore the pre-v0.2.0 flat
shape. If `len(findings) > 500`, the response is capped and surfaces
`pagination.auto_capped: true` with `total_before_cap` + `kept` counts.

**PCI DSS Requirements:** All 14 covered requirements (3.2.1, 3.3.1, 3.4.1, 3.5.1, 4.2.1, 6.2.4, 6.3.3, 6.4.3, 8.3.1, 8.3.6, 8.4.2, 8.6.2, 10.2.1, 11.6.1)

**Example output (abbreviated):**
```
PCI DSS v4.0.1 Compliance Report
Target: ./internal
Duration: 245ms | Files: 42 | Lines: 3200

3 CRITICAL, 1 HIGH, 0 MEDIUM findings

--- Requirement 3: Protect Stored Account Data ---

[CRITICAL] 3.3.1 -- SAD Not Retained After Authorization
  payment/handler.go:45
  PAN variable 'cardNumber' logged via slog.Info
  Fix: Remove PAN from log arguments or mask before logging

Compliance status: FAIL (4 active findings requiring action)
```

---

## scan_pan_data

Detect PAN/CVV exposure in Go source files and .env configuration.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |
| `cursor` | string | no | Opaque pagination cursor (v0.2.0+). Empty = fresh scan. Non-empty = resume from `scanner/hybridcache` (10-minute TTL; cursors are tool-scoped and not interchangeable with `generate_compliance_report` / `triage_findings`) |

**Pagination and cursor (v0.2.0+):** when the finding count exceeds 60,
the first response returns 60 findings plus `next_cursor`. Re-invoke
with `cursor` set to the previous `next_cursor` to fetch the next page.
Cursors are tool-scoped — a `scan_pan_data` cursor is rejected by the
other two tools with `CURSOR_MALFORMED`. Expired cursors (10-minute TTL)
return `CURSOR_EXPIRED`; re-run without a cursor to start fresh.

**PCI DSS Requirements:** 3.3.1, 3.4.1, 3.5.1

**Rules:** PAN-KEYWORD, PAN-LITERAL, PAN-TYPE, PAN-LOGGER, PAN-ZEROING

**Example output:**
```
1 CRITICAL, 0 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] PAN variable 'cardNumber' passed to fmt.Fprintf (Requirement 3.4.1)
  payment/handler.go:45
  Suggestion: Mask PAN to show only first 6 and last 4 digits
```

---

## check_encryption

Detect weak cryptographic algorithms, hardcoded keys, and plain HTTP usage.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 6.2.4, 4.2.1

**Rules:** CRYPTO-HARDCODED-KEY, CRYPTO-WEAK-HASH, CRYPTO-PLAIN-HTTP

**Example output:**
```
1 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] Hardcoded secret in variable 'encryptionKey' (Requirement 6.2.4)
  crypto/keys.go:12
  Suggestion: Move secrets to environment variables or a secrets manager
---
[HIGH] Weak hash algorithm md5.New() used in security context (Requirement 6.2.4)
  auth/hash.go:28
  Suggestion: Use SHA-256 or stronger
```

---

## check_tls_config

Detect TLS misconfigurations: InsecureSkipVerify, weak protocol versions, weak cipher suites.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 4.2.1

**Rules:** TLS-INSECURE-SKIP-VERIFY, TLS-WEAK-VERSION, TLS-MISSING-MIN-VERSION, TLS-WEAK-CIPHER

**Example output:**
```
1 CRITICAL, 0 HIGH, 1 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] InsecureSkipVerify set to true (Requirement 4.2.1)
  client/http.go:32
  Suggestion: Remove InsecureSkipVerify or set to false
```

---

## check_secrets_in_configs

Detect secrets in configuration files (.env, .yaml, .json, .toml).

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 8.6.2

**Rules:** SEC-PREFIX, SEC-CONNSTR, SEC-CREDENTIAL-KEY, SEC-HIGH-ENTROPY

**Example output:**
```
1 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] Secret with known prefix detected: key 'db_password' (Requirement 8.6.2)
  config/prod.env:5
  Suggestion: Use environment variables or a secrets manager
```

---

## check_error_handling

Detect unsafe error detail exposure in HTTP handlers, especially payment-related routes.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 6.2.4

**Rules:** ERR-LEAK-DIRECT, ERR-LEAK-FORMAT, ERR-LEAK-WRITE, ERR-LEAK-ENCODE

**Example output:**
```
0 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[HIGH] Error details written to HTTP response via fmt.Fprintf (Requirement 6.2.4)
  payment/handler.go:67
  Suggestion: Return generic error messages to clients; log details server-side
```

---

## check_auth_strength

Detect weak password policies, hardcoded credentials, and missing MFA on payment routes.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 8.3.1, 8.3.6, 8.4.2

**Rules:** AUTH-HARDCODED-PWD, AUTH-WEAK-POLICY, AUTH-BYTE-COUNT, AUTH-MISSING-MFA

**Example output:**
```
1 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] Hardcoded password detected (Requirement 8.3.1)
  auth/login.go:15
  Suggestion: Use environment variables or a secrets manager for credentials
```

---

## audit_log_coverage

Verify audit logging on payment-related HTTP handlers.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 10.2.1

**Rules:** AUDIT-NO-LOG, AUDIT-UNSTRUCTURED, AUDIT-LOG-OK

**Example output:**
```
0 CRITICAL, 2 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[HIGH] Payment handler has no audit logging (Requirement 10.2.1)
  payment/checkout.go:30
  Suggestion: Add structured logging (slog) with user ID, action, and timestamp
```

---

## check_data_retention

Detect CVV/PAN storage without TTL, Redis operations missing expiration, and memory zeroing issues.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 3.2.1, 3.3.1

**Rules:** RET-REDIS-NO-TTL, RET-REDIS-KEEP-TTL, RET-REDIS-NO-EXPIRE, RET-DB-SENSITIVE-STORE, RET-GORM-SENSITIVE-STORE, RET-CONFIG-NO-TTL, RET-ZERO-BEFORE-AUTH, RET-ZERO-DEFER-ONLY, RET-ZERO-AFTER-RESPONSE

**Example output:**
```
0 CRITICAL, 1 HIGH, 1 MEDIUM, 0 LOW, 0 INFO findings
[HIGH] Sensitive data stored in Redis without TTL (Requirement 3.2.1)
  cache/session.go:42
  Suggestion: Set expiration using SetEx or Expire for sensitive data keys
```

---

## check_payment_page_scripts

Check CSP headers, SRI attributes, and nonce usage on Go HTTP handlers and HTML templates.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to scan |

**PCI DSS Requirements:** 6.4.3, 11.6.1

**Rules:** CSP-MISSING, CSP-UNSAFE-INLINE, CSP-UNSAFE-EVAL, CSP-NO-SCRIPT-SRC, SRI-MISSING, SRI-MISSING-PAYMENT, NONCE-MISSING, NONCE-MISSING-PAYMENT, META-CSP-UNSAFE, META-CSP-ONLY, FIM-REQUIRED

**Example output:**
```
1 CRITICAL, 1 HIGH, 0 MEDIUM, 0 LOW, 0 INFO findings
[CRITICAL] No Content-Security-Policy header in payment handler (Requirement 6.4.3)
  web/server.go:55
  Suggestion: Add CSP header with script-src directive
```

---

## check_dependencies

Scan go.mod dependencies for known vulnerabilities via OSV.dev database.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to project directory containing go.mod |
| `mode` | string | no | Scan mode: `auto` (default), `online`, `offline` |

**PCI DSS Requirements:** 6.3.3

**Rules:** DEP-VULN, DEP-CACHE-STALE

**Example output:**
```
2 CRITICAL, 0 HIGH, 0 MEDIUM, 1 LOW, 0 INFO findings
[CRITICAL] CVE-2024-1234 in golang.org/x/net@v0.17.0 (CVSS 9.8) (Requirement 6.3.3)
  go.mod:15
  Suggestion: Upgrade to golang.org/x/net@v0.23.0 or later
```

---

## update_vulnerability_db

Refresh the local OSV vulnerability cache for offline `check_dependencies`
runs. Useful for air-gapped CI/CD environments and bank/fintech networks
where OSV.dev cannot be reached at scan time.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ecosystem` | string | no | Package ecosystem to refresh. Default `Go` |

**PCI DSS Requirements:** 6.3.3 (operational enabler)

**Example output:**
```
Updated vulnerability database: Go ecosystem
  Entries: 4,821
  Cache location: ~/.cache/pci-dss-mcp/osv/Go.json
  Last refresh: 2025-01-15T12:00:00Z
```

Run this periodically (daily via cron, or at the start of each CI build)
and then pass `mode: "offline"` to `check_dependencies` to scan without
network access.

---

## triage_findings

Run a full compliance scan and enrich each active finding with AI-triage
context: file/line `ResourceLink` hints for on-demand source reading,
imports, package declarations, detected middleware chains, framework
hints, and a per-finding triage hint. Designed to be chained after
`generate_compliance_report` or called standalone.

Verified-OK markers (rule IDs ending in `-OK`, currently `AUDIT-LOG-OK`
and `CSP-OK`) are **skipped before enrichment** per — they appear
in `generate_compliance_report` for auditor visibility but carry no
actionable signal for AI triage and previously consumed ~72% of the
triage payload on real projects.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | yes | Path to the project directory to triage |
| `dep_scan_mode` | string | no | Same semantics as `generate_compliance_report` |
| `include_tests` | bool | no | Include `_test.go` files. Default `false` |
| `include_taint` | bool | no | Same tri-state as `generate_compliance_report`. Default `true` (matches compliance report for parity ) |
| `min_severity` | string | no | Same as `generate_compliance_report` — applied BEFORE enrichment to avoid paying the per-finding context-collection cost on filtered-out findings |
| `rule_filter` | string | no | Same as `generate_compliance_report` |
| `limit` | int | no | Same as `generate_compliance_report` |
| `cursor` | string | no | Opaque pagination cursor (v0.2.0+). Empty = fresh scan. Non-empty = resume from session cache (10-minute TTL) |

**Pagination and cursor (v0.2.0+):** the first response caches the full
filtered finding slice in the `scanner/hybridcache` session store (shared
with `scan_pan_data`, but cursors are tool-scoped and not interchangeable),
enriches the first 60 findings with `ResourceLink` context, and sets
`next_cursor` when more pages remain. Follow-up calls with `cursor` set
read from the cache, enrich the next 60 findings, and update
`next_cursor`. `findings_total` always reports the pre-pagination count
so `generate_compliance_report` and `triage_findings` agree on scope
(parity contract preserved). Cursors are tool-scoped; cross-tool replay
returns `CURSOR_MALFORMED`. Expired cursors (10-minute TTL) return
`CURSOR_EXPIRED`.

**PCI DSS Requirements:** spans all requirements covered by
`generate_compliance_report`

**Output shape (post-19.4, MCP spec 2025-06-18):**

Returns a `TriageResult` via the SDK's `structuredContent` channel. Each
`EnrichedFinding` carries the original `scanner.Finding` plus:

```
context:
  sources: []ResourceLink      # file:// URIs + start_line/end_line hints
                               # (client reads source via its own Read tool)
  imports: []string             # top-of-file imports for language context
  package_decls: []string       # package-level decls near the finding
  middleware_chain: []string    # detected auth/logging/metrics middleware
  router_setup: string          # framework + route registration evidence
  response_type: string         # JSON / HTML / redirect classification
  declaration_scope: string     # local / package / exported
  evidence_files: []string      # cross-file evidence paths
  file_location: string         # project-relative classification
  triage_notes: string # / investigator notes
triage_hint: string              # one-line classification hint
```

**Example output (1-line text summary; full payload in `structuredContent`):**
```
46 findings triaged in 1432ms (7 files analyzed). Structured results in tool output.
```

**Wire size on real projects** (taint ON): ~41 KB for 46 findings
(reference payment service post-19.4 baseline). Under Anthropic's
"Code execution with MCP" ≤50 KB guidance.

---

## explain_requirement

Look up any PCI DSS v4.0.1 requirement by ID. Returns title, description, and testing procedure.

**Parameters:**
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `requirement_id` | string | yes | PCI DSS v4.0.1 requirement ID (e.g., `3.3.1`, `8.3.6`) |

**Example output:**
```
PCI DSS v4.0.1 - Requirement 3.3.1
Title: SAD Not Retained After Authorization

Description:
Sensitive authentication data (SAD) is not retained after authorization...

Testing Procedure:
Examine system configurations and data stores to verify SAD is not retained...
```
