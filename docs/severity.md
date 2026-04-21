# Severity Model

pci-dss-mcp uses five severity levels to classify findings.

## Severity Levels

| Level | Meaning | Pipeline Impact |
|-------|---------|-----------------|
| **CRITICAL** | Direct PCI DSS violation. Immediate remediation required. | Blocks pipeline |
| **HIGH** | Potential PCI DSS violation. Investigation and fix required. | Blocks pipeline |
| **MEDIUM** | Best practice violation. Should be addressed promptly. | Blocks pipeline |
| **LOW** | Low-severity finding. Track for documentation and review. | Does not block |
| **INFO** | Informational finding. No compliance action required. | Does not block |

## Active vs Informational

Findings are split into two categories:

- **Active Findings** (CRITICAL, HIGH, MEDIUM) -- PCI DSS compliance action required. These cause a FAIL compliance status in the report.
- **Informational** (LOW, INFO) -- No compliance SLA. Tracked for documentation but do not block pipelines or cause FAIL status.

## Severity is Requirement-Driven

Severity is fixed per rule and tied to its PCI DSS requirement. It does not change based on context. A PAN in a logger is always CRITICAL regardless of where in the codebase it appears.

Context affects confidence, not severity. Both high-confidence and low-confidence findings are reported at the same severity. Use `pci-ignore` comments to suppress false positives rather than expecting severity downgrade.

## Rule-to-Severity Mapping

### PAN Scanner (scan_pan_data)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| PAN-KEYWORD | CRITICAL | 3.5.1 or 3.3.1 (dynamic -- see docs/requirement-mapping.md) | PAN variable name in sensitive context; PAN fields route to 3.5.1, SAD fields (CVV/CVC/PIN/track) route to 3.3.1 |
| PAN-LITERAL | CRITICAL | 3.4.1 | Hardcoded card number matching Luhn + IIN |
| PAN-TYPE | HIGH | 3.5.1 | PAN-related type in sensitive context (string immutability prevents zeroing) |
| PAN-LOGGER | CRITICAL | 3.5.1 or 3.3.1 (dynamic -- see docs/requirement-mapping.md) | PAN variable passed to logging function; PAN fields route to 3.5.1 (related 3.4.1, 10.2.1), SAD fields route to 3.3.1 |
| PAN-ZEROING | MEDIUM | 3.5.1 | PAN variable not zeroed after use |

### Encryption Scanner (check_encryption)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| CRYPTO-HARDCODED-KEY | CRITICAL | 6.2.4 | Hardcoded encryption key (keyword match) |
| CRYPTO-HARDCODED-KEY | HIGH | 6.2.4 | Possible hardcoded key (entropy/pattern match) |
| CRYPTO-WEAK-HASH | HIGH | 6.2.4 | Weak hash algorithm (MD5, SHA-1) in security context |
| CRYPTO-PLAIN-HTTP | HIGH | 4.2.1 | Plain HTTP URL for sensitive endpoint |

### TLS Scanner (check_tls_config)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| TLS-INSECURE-SKIP-VERIFY | CRITICAL | 4.2.1 | InsecureSkipVerify set to true |
| TLS-WEAK-VERSION | HIGH | 4.2.1 | TLS version below 1.2 |
| TLS-MISSING-MIN-VERSION | MEDIUM | 4.2.1 | tls.Config without MinVersion set |
| TLS-WEAK-CIPHER | MEDIUM | 4.2.1 | Weak cipher suite in CipherSuites |

### Secrets Scanner (check_secrets_in_configs)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| SEC-PREFIX | CRITICAL | 8.6.2 | Secret with known provider prefix (AWS, GitHub, etc.) |
| SEC-CONNSTR | CRITICAL | 8.6.2 | Connection string with embedded credentials |
| SEC-CREDENTIAL-KEY | HIGH | 8.6.2 | Config key name matches credential pattern |
| SEC-HIGH-ENTROPY | HIGH | 8.6.2 | High-entropy value in credential-like key |

### Error Handling Scanner (check_error_handling)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| ERR-LEAK-DIRECT | HIGH | 6.2.4 | Error written directly to HTTP response |
| ERR-LEAK-FORMAT | HIGH | 6.2.4 | Error formatted into HTTP response via fmt |
| ERR-LEAK-WRITE | HIGH | 6.2.4 | Error written to ResponseWriter |
| ERR-LEAK-ENCODE | HIGH | 6.2.4 | Error encoded into JSON response |

### Authentication Scanner (check_auth_strength)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| AUTH-HARDCODED-PWD | CRITICAL | 8.6.2 | Hardcoded password in source code (related: 8.3.1 auth factor requirement) |
| AUTH-WEAK-POLICY | HIGH | 8.3.6 | Password length check below 12 characters |
| AUTH-BYTE-COUNT | MEDIUM | 8.3.6 | Password length in bytes, not characters |
| AUTH-MISSING-MFA | HIGH | 8.4.2 | Payment route without MFA middleware |

### Audit Log Scanner (audit_log_coverage)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| AUDIT-NO-LOG | HIGH | 10.2.1 | Payment handler has no audit logging |
| AUDIT-UNSTRUCTURED | HIGH | 10.2.1 | Uses fmt/log instead of structured logging |
| AUDIT-LOG-OK | INFO | 10.2.1 | Handler has adequate logging (informational) |

### Data Retention Scanner (check_data_retention)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| RET-REDIS-NO-TTL | HIGH | 3.2.1 | Sensitive data stored in Redis without TTL |
| RET-REDIS-KEEP-TTL | MEDIUM | 3.2.1 | Redis KeepTTL used with sensitive data |
| RET-REDIS-NO-EXPIRE | HIGH | 3.2.1 | Redis key without Expire call |
| RET-DB-SENSITIVE-STORE | HIGH | 3.2.1 | Sensitive data stored in DB without retention policy |
| RET-GORM-SENSITIVE-STORE | HIGH | 3.2.1 | Sensitive data stored via GORM without retention |
| RET-CONFIG-NO-TTL | MEDIUM | 3.2.1 | Config specifies storage without TTL |
| RET-ZERO-BEFORE-AUTH | MEDIUM | 3.2.1 | Sensitive variable zeroed before authorization check |
| RET-ZERO-DEFER-ONLY | LOW | 3.2.1 | Sensitive variable zeroed only via defer |
| RET-ZERO-AFTER-RESPONSE | MEDIUM | 3.2.1 | Sensitive variable zeroed after HTTP response |

### Payment Page Scripts Scanner (check_payment_page_scripts)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| CSP-MISSING | CRITICAL | 6.4.3 | No CSP header on payment handler |
| CSP-UNSAFE-INLINE | HIGH | 6.4.3 | CSP allows unsafe-inline for scripts |
| CSP-UNSAFE-EVAL | HIGH | 6.4.3 | CSP allows unsafe-eval |
| CSP-NO-SCRIPT-SRC | HIGH | 6.4.3 | CSP present but missing script-src directive |
| CSP-VALUE-UNANALYZABLE | MEDIUM | 6.4.3 | CSP value set dynamically, cannot analyze |
| CSP-OK | INFO | 6.4.3 | CSP header present and adequate |
| SRI-MISSING | MEDIUM | 6.4.3 | External script without SRI integrity attribute |
| SRI-MISSING-PAYMENT | HIGH | 6.4.3 | External script in payment template without SRI |
| NONCE-MISSING | MEDIUM | 6.4.3 | Inline script without nonce attribute |
| NONCE-MISSING-PAYMENT | HIGH | 6.4.3 | Inline script in payment template without nonce |
| META-CSP-UNSAFE | HIGH | 6.4.3 | Meta tag CSP with unsafe directives |
| META-CSP-ONLY | MEDIUM | 6.4.3 | CSP only in meta tag, not HTTP header |
| FIM-REQUIRED | HIGH | 11.6.1 | File integrity monitoring required for payment pages |

### SQL Scanner (report-only, via generate_compliance_report)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| SQL-SENSITIVE-COLUMN | HIGH | 3.5.1 or 3.3.1 (dynamic -- see docs/requirement-mapping.md) | Sensitive column detected in CREATE TABLE; PAN columns route to 3.5.1, SAD columns route to 3.3.1 |
| SQL-TEXT-TYPE | HIGH | 3.5.1 | Plaintext column type (text/varchar) for sensitive column |
| GORM-SENSITIVE-TAG | HIGH | 3.5.1 or 3.3.1 (dynamic -- see docs/requirement-mapping.md) | GORM tag references sensitive column; PAN routes to 3.5.1, SAD routes to 3.3.1 |
| GORM-NO-ENCRYPT-HOOK | HIGH | 3.5.1 | GORM model missing BeforeCreate/BeforeSave encrypt hook |

### Dependency Scanner (check_dependencies)

| Rule ID | Severity | Requirement | Description |
|---------|----------|-------------|-------------|
| DEP-VULN | varies | 6.3.3 | Known vulnerability in dependency (severity from CVSS) |
| DEP-CACHE-STALE | LOW | 6.3.3 | Vulnerability cache is older than 7 days |
