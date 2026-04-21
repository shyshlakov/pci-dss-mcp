# PCI DSS Requirement Mapping

Canonical source of truth for the requirement_id every scanner rule_id maps to.
The guard test in `scanner/requirement_mapping_test.go` enforces drift between
this table and the source emit sites. Any rule whose primary/related requirement
changes in source MUST also update this file, or the test fails in CI.

Rules marked `dynamic emit` in `coverage_note` are waived from the exact source
tuple check because their requirement_id is computed via a helper (the guard
test still asserts the rule_id exists in source).

| rule_id | primary | related | scanner | coverage | coverage_note |
|---------|---------|---------|---------|----------|---------------|
| AUDIT-LOG-OK | 10.2.1 |  | auditscanner | metadata-only | verified-OK marker; auditor-visible evidence that audit logging was observed |
| AUDIT-NO-LOG | 10.2.1 |  | auditscanner | partial (static-only, needs QSA) | detects absence of structured logging; 10.2.1 field completeness (user_id, timestamp, action, outcome, origin) is manual |
| AUDIT-UNSTRUCTURED | 10.2.1 |  | auditscanner | full | unstructured logging (fmt.Println) fails the "audit logs are enabled and active" spirit of 10.2.1 |
| AUTH-BYTE-COUNT | 8.3.6 |  | authscanner | partial (static-only, needs QSA) | indirect — char vs byte length alignment with 8.3.6 minimum-12-characters spirit |
| AUTH-HARDCODED-PWD | 8.6.2 | 8.3.1 | authscanner | full | hardcoded secret in source code is a direct 8.6.2 violation; 8.3.1 auth-factor link in related |
| AUTH-MISSING-MFA | 8.4.2 |  | authscanner | partial (static-only, needs QSA) | 8.4.2 allows infrastructure-level MFA (gateway, service mesh); static scanner flags missing app-layer middleware only |
| AUTH-WEAK-POLICY | 8.3.6 |  | authscanner | full | password-policy threshold below 12 characters is a direct 8.3.6 violation |
| AUTH-WEBHOOK-NO-SIGNATURE | 6.2.4 |  | authscanner | full | missing webhook signature verification falls under the 6.2.4 input-validation + deserialization clauses |
| AUTH-WEBHOOK-VERIFIED | 6.2.4 |  | authscanner | metadata-only | verified-OK marker emitted when webhook signature verification is detected |
| CRYPTO-HARDCODED-KEY | 6.2.4 | 8.6.2 | cryptoscanner | full | hardcoded cryptographic key in source is a 6.2.4 software-engineering violation; 8.6.2 links the hardcoded-secret angle |
| CRYPTO-PLAIN-HTTP | 4.2.1 |  | cryptoscanner | full | plain HTTP URL in a payment context violates the 4.2.1 strong-cryptography-in-transit clause |
| CRYPTO-WEAK-HASH | 6.2.4 |  | cryptoscanner | full | MD5/SHA1 on sensitive data falls under the 6.2.4 insecure-cryptographic-implementations clause |
| CSP-MISSING | 6.4.3 |  | scriptscanner | full | missing CSP header means the script-authorization mechanism required by 6.4.3 is absent |
| CSP-NO-SCRIPT-SRC | 6.4.3 |  | scriptscanner | full | CSP without script-src or default-src fails to authorize scripts per 6.4.3 |
| CSP-OK | 6.4.3 |  | scriptscanner | metadata-only | verified-OK marker emitted when a well-formed CSP is detected |
| CSP-UNSAFE-EVAL | 6.4.3 |  | scriptscanner | full | unsafe-eval defeats the 6.4.3 authorization clause |
| CSP-UNSAFE-INLINE | 6.4.3 |  | scriptscanner | full | unsafe-inline defeats the 6.4.3 authorization clause |
| CSP-VALUE-UNANALYZABLE | 6.4.3 |  | scriptscanner | partial (static-only, needs QSA) | CSP value set from a non-literal; static analysis cannot verify correctness |
| DEP-CACHE-STALE | 6.3.3 |  | depscanner | partial (static-only, needs QSA) | meta-finding; warns about stale vuln cache, not a direct 6.3.3 violation |
| DEP-VULN | 6.3.3 |  | depscanner | full | direct OSV.dev CVE match is a direct 6.3.3 violation under v4.0.1 patch SLAs |
| ERR-LEAK-DIRECT | 6.2.4 |  | errorscanner | full | direct err.Error() to response in payment context falls under 6.2.4 improper-error-handling |
| ERR-LEAK-ENCODE | 6.2.4 |  | errorscanner | full | encoding an error struct into the response body falls under 6.2.4 improper-error-handling |
| ERR-LEAK-FORMAT | 6.2.4 |  | errorscanner | full | fmt.Sprintf("%v", err) propagating to response falls under 6.2.4 improper-error-handling |
| ERR-LEAK-WRITE | 6.2.4 |  | errorscanner | full | w.Write of err.Error() falls under 6.2.4 improper-error-handling |
| FIM-REQUIRED | 11.6.1 |  | scriptscanner | partial (static-only, needs QSA) | advisory — static analysis cannot verify runtime payment-page change detection |
| GORM-ENCRYPT-OK | 3.5.1 |  | sqlscanner | metadata-only | dynamic emit — verified-OK marker assigned post-scan when a custom GORM column type's Value() body is verified to call AES-GCM / NaCl secretbox / ChaCha20 / a KMS helper |
| GORM-NO-ENCRYPT-HOOK | 3.5.1 |  | sqlscanner | full | missing BeforeCreate/BeforeSave encrypt hook on a sensitive GORM column is a direct 3.5.1 violation |
| GORM-SENSITIVE-TAG | 3.5.1 |  | sqlscanner | full | dynamic emit — PAN-classified gorm column primary 3.5.1; SAD-classified routes to 3.3.1 via sensitivedata.Classify |
| META-CSP-ONLY | 6.4.3 |  | scriptscanner | full | meta-tag CSP is weaker than the HTTP-header CSP required by 6.4.3 |
| META-CSP-UNSAFE | 6.4.3 |  | scriptscanner | full | meta-tag CSP with unsafe-* directives fails the 6.4.3 authorization clause |
| NONCE-MISSING | 6.4.3 |  | scriptscanner | full | inline script without nonce violates the 6.4.3 script-authorization clause |
| NONCE-MISSING-PAYMENT | 6.4.3 |  | scriptscanner | full | inline script without nonce on a payment page; escalated severity per 6.4.3 |
| PAN-KEYWORD | 3.5.1 |  | panscanner | full | dynamic emit — PAN-classified field/tag routes to 3.5.1; SAD-classified routes to 3.3.1 + [3.3.1.2] via sensitivedata.Classify; .env PAN-KEYWORD retains 3.3.1 + [3.3.1.2] |
| PAN-LITERAL | 3.4.1 |  | panscanner | full | PAN literal in source exposed on the display/log surface; 3.4.1 display-masking violation |
| PAN-LOGGER | 3.5.1 | 3.4.1, 10.2.1 | panscanner | full | dynamic emit — PAN-classified logger argument routes to 3.5.1 + [3.4.1, 10.2.1]; SAD-classified routes to 3.3.1 + [3.3.1.2] via sensitivedata.Classify |
| PAN-TYPE | 3.5.1 |  | panscanner | partial (static-only, needs QSA) | memory-hygiene angle of 3.5.1; string immutability prevents zeroing but is a secondary concern |
| PAN-ZEROING | 3.5.1 |  | panscanner | partial (static-only, needs QSA) | memory lifecycle; 3.5.1 is primarily about stored data rendered unreadable |
| RET-CONFIG-NO-TTL | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | static analysis detects programmatic retention controls only; does NOT verify retention policy existence or quarterly review |
| RET-DB-SENSITIVE-STORE | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | static analysis detects programmatic retention controls only; does NOT verify retention policy existence or quarterly review |
| RET-GORM-SENSITIVE-STORE | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | static analysis detects programmatic retention controls only; does NOT verify retention policy existence or quarterly review |
| RET-REDIS-KEEP-TTL | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | KeepTTL edge case; static analysis detects programmatic retention controls only |
| RET-REDIS-NO-EXPIRE | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | HSet without Expire; static analysis detects programmatic retention controls only |
| RET-REDIS-NO-TTL | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | Redis without TTL; static analysis detects programmatic retention controls only |
| RET-ZERO-AFTER-RESPONSE | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | SAD memory lifecycle; 3.3.1 may be a better fit long-term (see deferred §5.7) |
| RET-ZERO-BEFORE-AUTH | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | SAD memory lifecycle; 3.3.1 may be a better fit long-term (see deferred §5.7) |
| RET-ZERO-DEFER-ONLY | 3.2.1 |  | retentionscanner | partial (static-only, needs QSA) | SAD memory lifecycle; 3.3.1 may be a better fit long-term (see deferred §5.7) |
| SEC-CONNSTR | 8.6.2 |  | secretscanner | full | DB system-account password inside a connection string is a direct 8.6.2 violation |
| SEC-CREDENTIAL-KEY | 8.6.2 |  | secretscanner | full | credential key = system-account login material; direct 8.6.2 violation |
| SEC-HIGH-ENTROPY | 8.6.2 |  | secretscanner | partial (static-only, needs QSA) | high-entropy string near a credential key; probabilistic, manual review recommended |
| SEC-PREFIX | 8.6.2 |  | secretscanner | full | known API-key prefixes (sk_, ghp_, AKIA, ...) are broadly recognised 8.6.2 leakage |
| SQL-SENSITIVE-COLUMN | 3.5.1 |  | sqlscanner | full | dynamic emit — PAN-classified column routes to 3.5.1; SAD-classified routes to 3.3.1 via sensitivedata.Classify |
| SQL-TEXT-TYPE | 3.5.1 |  | sqlscanner | full | plaintext column type for PAN/SAD is a direct 3.5.1 violation |
| SRI-MISSING | 6.4.3 |  | scriptscanner | full | missing integrity attribute on external script violates the 6.4.3 integrity clause |
| SRI-MISSING-PAYMENT | 6.4.3 |  | scriptscanner | full | missing integrity attribute on a payment-page script; escalated severity per 6.4.3 |
| SUPPRESSED-PACKAGE | n/a |  | reportscanner | metadata-only | suppression audit trail marker; not a compliance finding |
| TLS-INSECURE-SKIP-VERIFY | 4.2.1 | 4.2.1.1, 2.2.7 | tlsscanner | full | InsecureSkipVerify disables cert validation; 4.2.1 requires validated certs; 4.2.1.1 adds cert inventory, 2.2.7 adds secure-services config |
| TLS-MISSING-MIN-VERSION | 4.2.1 |  | tlsscanner | full | unspecified MinVersion leaves the Go default variable; 4.2.1 requires a known-strong floor |
| TLS-WEAK-CIPHER | 4.2.1 |  | tlsscanner | full | RC4/3DES/NULL/EXPORT ciphers are prohibited under 4.2.1 strong-cryptography |
| TLS-WEAK-VERSION | 4.2.1 |  | tlsscanner | full | TLS 1.0 or 1.1 is below the 4.2.1 baseline of TLS 1.2 |
