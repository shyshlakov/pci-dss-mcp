---
fixture_version: 1.13
last_updated: 2026-07-07
phase: 21.1
plan: 01
total_intentional_violations: 163
total_clean_patterns: 28
total_rules_covered: 57
expected_summary:
 critical: 51
 high: 95
 medium: 54
 low: 0
 info: 66
expected_active: 213
expected_total_findings: 262
expected_sbom_components: 40
expected_sbom_format: cyclonedx-json
expected_sbom_spec_version: "1.6"
expected_sbom_serial_format: urn-uuid-v4
expected_sbom_metadata_component: present
expected_sbom_tools_self_hash: optional
pci_6_3_2_status: PASS
rules_coverage:
 panscanner: [PAN-KEYWORD, PAN-TYPE, PAN-LITERAL, PAN-LOGGER, PAN-ZEROING]
 cryptoscanner: [CRYPTO-WEAK-HASH, CRYPTO-HARDCODED-KEY, CRYPTO-PLAIN-HTTP]
 tlsscanner: [TLS-INSECURE-SKIP-VERIFY, TLS-MISSING-MIN-VERSION, TLS-WEAK-VERSION, TLS-WEAK-CIPHER]
 secretscanner: [SEC-PREFIX, SEC-HIGH-ENTROPY, SEC-CONNSTR, SEC-CREDENTIAL-KEY]
 errorscanner: [ERR-LEAK-DIRECT, ERR-LEAK-FORMAT, ERR-LEAK-WRITE, ERR-LEAK-ENCODE]
 authscanner: [AUTH-HARDCODED-PWD, AUTH-WEAK-POLICY, AUTH-MISSING-MFA, AUTH-BYTE-COUNT, AUTH-WEBHOOK-NO-SIGNATURE, AUTH-WEBHOOK-VERIFIED]
 auditscanner: [AUDIT-NO-LOG, AUDIT-UNSTRUCTURED, AUDIT-LOG-OK]
 retentionscanner: [RET-DB-SENSITIVE-STORE, RET-GORM-SENSITIVE-STORE, RET-REDIS-NO-TTL, RET-REDIS-KEEP-TTL, RET-REDIS-NO-EXPIRE, RET-CONFIG-NO-TTL, RET-ZERO-BEFORE-AUTH, RET-ZERO-AFTER-RESPONSE, RET-ZERO-DEFER-ONLY]
 scriptscanner: [CSP-MISSING, CSP-OK, CSP-UNSAFE-INLINE, CSP-UNSAFE-EVAL, CSP-NO-SCRIPT-SRC, CSP-VALUE-UNANALYZABLE, META-CSP-ONLY, META-CSP-UNSAFE, SRI-MISSING, SRI-MISSING-PAYMENT, NONCE-MISSING, NONCE-MISSING-PAYMENT, FIM-REQUIRED]
 depscanner: [DEP-VULN, DEP-CACHE-COLD, DEP-CACHE-STALE, DEP-CACHE-NO-DIR]
 sqlscanner: [SQL-SENSITIVE-COLUMN, SQL-TEXT-TYPE, GORM-SENSITIVE-TAG, GORM-NO-ENCRYPT-HOOK, GORM-ENCRYPT-OK]
known_gaps: []
pending_rules: []
---

# Expected Findings — Vulnerable Payment Service Fixture

This file is the machine-readable contract consumed by
`scanner/reportscanner/fixture_test.go`. The frontmatter is parsed with
`yaml.v3`; the body table is parsed with a simple pipe-row regex. Do NOT
reformat the tables without updating the test parser.

The contract reflects the current scanner baseline. The `known_gaps`
section documents fixture violations that are not yet detected — they
are intentional targets for future scanner improvements. When a scanner
learns one of these patterns, the row moves from `known_gaps` into the
`## Violations` table in the same commit.

The `pending_rules` section lists violations that require a future
scanner enhancement. The test parser ignores `pending_rules`
(informational only). Move entries to `## Violations` once the
corresponding scanner change is implemented.

Line numbers track the current scanner output; update this file whenever
fixture files change.

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 51 |
| HIGH | 95 |
| MEDIUM | 53 |
| LOW | 0 |
| INFO | 66 |

## Violations

| Rule ID | Severity | File | Line | Req ID | Related | Notes |
|---------|----------|------|------|--------|---------|-------|
| AUDIT-LOG-OK | INFO | internal/http/handler/tokens/tokenize.go | 11 |  |  | logrus structured fields PCI 10.2.1 partial coverage |
| AUDIT-LOG-OK | INFO | internal/http_input/conditional_debug.go | 11 | 10.2.1 |  | structured slog.Info inside conditional debug branch |
| AUDIT-LOG-OK | INFO | internal/http_input/json_struct_log.go | 15 | 10.2.1 |  | structured slog.Any LogJSONStruct |
| AUDIT-NO-LOG | CRITICAL | clean/s2s_handler/generic_consensus_webhook.go | 12 |  |  | incidental AUDIT-NO-LOG on s2s fixture handler |
| AUDIT-NO-LOG | CRITICAL | internal/auth/process.go | 5 |  |  | AuthorizeCharge handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/callback/mastercard.go | 8 |  |  | S2S callback handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/checkout.go | 8 |  |  | RenderCheckout no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/dynamic.go | 8 |  |  | RenderCheckoutDynamic handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/eval.go | 8 |  |  | RenderCheckoutEval handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/inline.go | 8 |  |  | RenderCheckoutInline handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/noscript.go | 8 |  |  | RenderCheckoutNoScript handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/payment/charge.go | 5 |  |  | charge handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/payment/clean.go | 8 |  |  | RenderCheckoutClean handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/tokens/exchange.go | 5 |  |  | TokenizeCardExchange handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/tokens/metadata.go | 8 |  |  | CardMetadata handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/webhook/bad_generic_webhook.go | 12 |  |  | incidental AUDIT-NO-LOG on webhook bad fixture |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/webhook/bad_paypal_ipn.go | 12 |  |  | incidental AUDIT-NO-LOG on webhook bad fixture |
| AUDIT-NO-LOG | CRITICAL | internal/http_input/error_taint.go | 12 | 10.2.1 |  | ConfirmCharge handler body has no log call (logging happens in AbortWithErrorLog helper) |
| AUDIT-NO-LOG | HIGH | internal/billing/encode_map.go | 19 |  |  | EncodeHandler no log calls after fixture-shortcut removal |
| AUDIT-NO-LOG | HIGH | internal/http_input/central_abort_log.go | 12 | 10.2.1 |  | GetMerchant handler body has no log call (logging happens in Abort helper) |
| AUDIT-NO-LOG | HIGH | internal/payment/zeroing_init.go | 20 |  |  | incidental tier-2 AUDIT-NO-LOG on fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_elseif.go | 7 |  |  | RED: incidental tier-2 AUDIT-NO-LOG on Z9 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_select.go | 10 |  |  | RED: incidental tier-2 AUDIT-NO-LOG on Z12 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_switch.go | 7 |  |  | RED: incidental tier-2 AUDIT-NO-LOG on Z10 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_typeswitch.go | 7 |  |  | RED: incidental tier-2 AUDIT-NO-LOG on Z11 fixture |
| AUDIT-NO-LOG | HIGH | internal/tokens/delegation/delegating.go | 19 |  |  | RED: incidental tier-2 AUDIT-NO-LOG on delegation-only Wrapper.ServeHTTP (stays flagged after because audit scanner is not in scope of this plan) |
| AUDIT-NO-LOG | CRITICAL | internal/util/cardproc.go | 5 |  |  | ProcessCardBuffer handler no log calls |
| AUDIT-UNSTRUCTURED | CRITICAL | internal/http/handler/tokens/detokenize.go | 8 |  |  | fmt.Println logging only |
| AUDIT-UNSTRUCTURED | HIGH | internal/billing/handler.go | 16 |  |  | tier-2 HIGH after fixture-shortcut removal |
| AUDIT-UNSTRUCTURED | HIGH | internal/exchange/handler.go | 10 |  |  | tier-2 HIGH after fixture-shortcut removal |
| AUDIT-UNSTRUCTURED | HIGH | internal/payment/core.go | 19 |  |  | tier-2 HIGH after fixture-shortcut removal |
| AUTH-BYTE-COUNT | MEDIUM | internal/auth/policy.go | 12 |  |  | len(password) byte count check |
| AUTH-HARDCODED-PWD | INFO | clean/testutil/db_fixture.go | 3 | 8.6.2 | 8.3.1 | testutil helper hardcoded password testutil_exclusion downgrade |
| AUTH-HARDCODED-PWD | CRITICAL | internal/auth/admin.go | 3 | 8.6.2 | 8.3.1 | const AdminPassword = "admin123" |
| AUTH-HARDCODED-PWD | CRITICAL | internal/payment/hardcoded_admin.go | 3 | 8.6.2 | 8.3.1 | prod path hardcoded admin password stays CRITICAL adversarial |
| AUTH-MISSING-MFA | INFO | clean/s2s_handler/generic_consensus_webhook.go | 9 |  |  | downgrade:s2s_handler T2+T3 consensus name regex + /hooks/ path + POST + no Authorization read |
| AUTH-MISSING-MFA | INFO | clean/s2s_handler/stripe_hmac_webhook.go | 13 |  |  | downgrade:s2s_handler T1 strong hmac.Equal before json.Unmarshal |
| AUTH-MISSING-MFA | HIGH | internal/auth/process.go | 5 |  |  | AuthorizeCharge handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/billing/encode_map.go | 19 |  |  | EncodeHandler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/billing/handler.go | 16 |  |  | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/exchange/handler.go | 10 |  |  | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/http/handler.go | 10 |  |  | router has no MFA middleware |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/admin/admin_panel.go | 9 |  |  | D-03 negative signal: http.SetCookie write keeps HIGH despite webhook-shaped name |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/callback/mastercard.go | 8 |  |  | callback handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/checkout.go | 8 |  |  | checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/dynamic.go | 8 |  |  | dynamic checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/eval.go | 8 |  |  | eval checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/inline.go | 8 |  |  | inline checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/noscript.go | 8 |  |  | noscript checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/payment/charge.go | 5 |  |  | charge handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/payment/clean.go | 8 |  |  | RenderCheckoutClean handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/detokenize.go | 8 |  |  | detokenize handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/exchange.go | 5 |  |  | TokenizeCardExchange handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/metadata.go | 8 |  |  | CardMetadata handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/tokenize.go | 11 |  |  | tokenize handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/payment/core.go | 19 |  |  | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/payment/zeroing_init.go | 20 |  |  | incidental AUTH-MISSING-MFA on fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_elseif.go | 7 |  |  | RED: incidental AUTH-MISSING-MFA on Z9 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_select.go | 10 |  |  | RED: incidental AUTH-MISSING-MFA on Z12 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_switch.go | 7 |  |  | RED: incidental AUTH-MISSING-MFA on Z10 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_typeswitch.go | 7 |  |  | RED: incidental AUTH-MISSING-MFA on Z11 fixture |
| AUTH-MISSING-MFA | HIGH | internal/util/cardproc.go | 5 |  |  | ProcessCardBuffer handler no MFA |
| AUTH-WEAK-POLICY | CRITICAL | internal/auth/policy.go | 12 |  |  | MinPasswordLength below PCI 8.3.6 |
| AUTH-WEBHOOK-NO-SIGNATURE | CRITICAL | internal/http/handler/callback/mastercard.go | 8 |  |  | fixture reuse — Mastercard brand path canonical anti-pattern |
| AUTH-WEBHOOK-NO-SIGNATURE | CRITICAL | internal/http/handler/webhook/bad_paypal_ipn.go | 12 |  |  | brand=paypal D-06 |
| AUTH-WEBHOOK-NO-SIGNATURE | CRITICAL | internal/http/handler/webhook/bad_stripe_webhook.go | 12 |  |  | brand=stripe Jack Cable canonical anti-pattern |
| AUTH-WEBHOOK-NO-SIGNATURE | HIGH | clean/s2s_handler/generic_consensus_webhook.go | 12 |  |  | incidental unsigned /hooks/payment webhook emission |
| AUTH-WEBHOOK-NO-SIGNATURE | HIGH | internal/http/handler/admin/admin_panel.go | 12 |  |  | incidental unsigned webhook-shaped handler emission |
| AUTH-WEBHOOK-NO-SIGNATURE | HIGH | internal/http/handler/webhook/bad_generic_webhook.go | 12 |  |  | generic /hooks/payment no brand keyword |
| AUTH-WEBHOOK-VERIFIED | INFO | clean/webhook_signed/good_hmac_generic.go | 16 |  |  | hmac.Equal T1 strong before parser |
| AUTH-WEBHOOK-VERIFIED | INFO | clean/webhook_signed/good_middleware_verified.go | 22 |  |  | webhookmiddleware crawler match (VerifyWebhookSignatureMiddleware wrapper) |
| AUTH-WEBHOOK-VERIFIED | INFO | clean/webhook_signed/good_stripe_constructevent.go | 19 |  |  | webhook.ConstructEvent T1 strong before parser |
| AUTH-WEBHOOK-VERIFIED | INFO | clean/webhook_signed/webhook_with_local_helper.go | 15 |  |  | D-07 1-level recursion verifyStripeSignature -> hmac.Equal |
| CRYPTO-HARDCODED-KEY | HIGH | internal/config/constants_file.go | 3 | 6.2.4 | 8.6.2 | F-25 Layer 4 path downgrade CRITICAL to HIGH tag crypto_key_constants_file |
| CRYPTO-HARDCODED-KEY | INFO | clean/crypto_filter_cases/header_const.go | 3 | 6.2.4 | 8.6.2 | F-25 Layer 2 header pattern downgrades to INFO tag hardcoded_header_name |
| CRYPTO-HARDCODED-KEY | INFO | clean/crypto_filter_cases/json_key.go | 3 | 6.2.4 | 8.6.2 | F-25 Layer 2 camelCase pattern downgrades to INFO tag hardcoded_json_key |
| CRYPTO-HARDCODED-KEY | INFO | clean/crypto_filter_cases/log_field.go | 3 | 6.2.4 | 8.6.2 | F-25 Layer 2 snake_case pattern downgrades to INFO tag hardcoded_log_field |
| CRYPTO-HARDCODED-KEY | INFO | clean/crypto_filter_cases/sentinel_error.go | 5 | 6.2.4 | 8.6.2 | F-25 Layer 1 AST errors.New guard downgrades to INFO tag hardcoded_sentinel_error |
| CRYPTO-HARDCODED-KEY | CRITICAL | clean/gorm_encrypt_type/real_encrypted/secure_string.go | 13 | 6.2.4 | 8.6.2 | F-26 D-08 defense-in-depth: hardcoded AES key in Value() method coexists with GORM-ENCRYPT-OK |
| CRYPTO-HARDCODED-KEY | CRITICAL | internal/auth/admin.go | 3 | 6.2.4 | 8.6.2 | hardcoded admin secret |
| CRYPTO-HARDCODED-KEY | HIGH | internal/auth/process.go | 6 | 6.2.4 | 8.6.2 | hardcoded sample literal in handler |
| CRYPTO-HARDCODED-KEY | CRITICAL | internal/crypto/keys.go | 3 | 6.2.4 | 8.6.2 | AESKey constant 32 hex chars |
| CRYPTO-HARDCODED-KEY | CRITICAL | internal/crypto/real_hardcoded_aes.go | 3 | 6.2.4 | 8.6.2 | F-25 adversarial 64-char hex AES-256 key stays CRITICAL through all layers |
| CRYPTO-HARDCODED-KEY | HIGH | internal/http/handler/payment/charge.go | 6 | 6.2.4 | 8.6.2 | hardcoded key inside payment handler |
| CRYPTO-HARDCODED-KEY | INFO | internal/testseed/constants.go | 3 | 6.2.4 | 8.6.2 | dev-context marker downgrades to INFO |
| CRYPTO-HARDCODED-KEY | HIGH | internal/util/cardops.go | 6 | 6.2.4 | 8.6.2 | hardcoded sample literal |
| CRYPTO-HARDCODED-KEY | HIGH | internal/util/cardproc.go | 6 | 6.2.4 | 8.6.2 | hardcoded sample literal |
| CRYPTO-PLAIN-HTTP | CRITICAL | internal/http/client.go | 8 |  |  | http://api.payment.example/charge |
| CRYPTO-WEAK-HASH | CRITICAL | internal/crypto/hash.go | 6 |  |  | md5.Sum on password input |
| CSP-MISSING | INFO | internal/auth/process.go | 5 |  |  | non-HTML payment handler informational note |
| CSP-MISSING | INFO | internal/billing/handler.go | 16 |  |  | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | INFO | internal/exchange/handler.go | 10 |  |  | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | HIGH | internal/http/handler/checkout/checkout.go | 8 |  |  | RenderCheckout no Content-Security-Policy header |
| CSP-MISSING | INFO | internal/http/handler/payment/charge.go | 5 |  |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/detokenize.go | 8 |  |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/exchange.go | 5 |  |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/tokenize.go | 11 |  |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http_input/conditional_debug.go | 11 | 6.4.3 |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http_input/json_struct_log.go | 15 | 6.4.3 |  | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/payment/core.go | 19 |  |  | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | INFO | internal/payment/zeroing_init.go | 20 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/retention/zeroing_elseif.go | 7 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/retention/zeroing_select.go | 10 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/retention/zeroing_switch.go | 7 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/retention/zeroing_typeswitch.go | 7 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/tokens/delegation/delegating.go | 19 |  |  | non-HTML handler informational note (path-dep live-only) |
| CSP-MISSING | INFO | internal/util/cardproc.go | 5 |  |  | non-HTML handler informational note |
| CSP-NO-SCRIPT-SRC | HIGH | internal/http/handler/checkout/noscript.go | 8 |  |  | CSP missing script-src and default-src |
| CSP-OK | INFO | internal/http/handler/payment/clean.go | 8 |  |  | verified valid CSP header set |
| CSP-UNSAFE-EVAL | HIGH | internal/http/handler/checkout/eval.go | 8 |  |  | script-src 'unsafe-eval' literal |
| CSP-UNSAFE-INLINE | HIGH | internal/http/handler/checkout/inline.go | 8 |  |  | script-src 'unsafe-inline' literal |
| CSP-VALUE-UNANALYZABLE | INFO | internal/http/handler/checkout/dynamic.go | 8 |  |  | CSP value sourced from variable |
| DEP-VULN | HIGH | go.mod | 7 |  |  | go-jose/v4 v4.1.3 advisory |
| DEP-VULN | MEDIUM | go.mod | 9 |  |  | gofiber/fiber/v2 v2.52.13 advisory GHSA-gcfq-8gqf-4876, no fixed v2 release |
| ERR-LEAK-DIRECT | CRITICAL | internal/http/handler/tokens/tokenize.go | 21 |  |  | http.Error(w, err.Error(), 500) |
| ERR-LEAK-ENCODE | CRITICAL | internal/billing/encode_map.go | 22 |  |  | map-literal err leak ( fixture) |
| ERR-LEAK-ENCODE | CRITICAL | internal/http/handler/tokens/metadata.go | 11 |  |  | json.NewEncoder(w).Encode(err) |
| ERR-LEAK-FORMAT | HIGH | internal/billing/handler.go | 19 |  |  | abstract HandleRequest name, /billing/ path + PAN field, multi-signal |
| ERR-LEAK-FORMAT | HIGH | internal/exchange/handler.go | 12 |  |  | abstract Execute name, go-jose SDK import, signal 3 |
| ERR-LEAK-FORMAT | HIGH | internal/http/handler/tokens/detokenize.go | 10 |  |  | fmt.Fprintf %v err |
| ERR-LEAK-FORMAT | HIGH | internal/payment/core.go | 19 |  |  | abstract Execute name, /payment/ path + *Card param, signal 2 + 4 |
| ERR-LEAK-WRITE | CRITICAL | internal/http/handler/tokens/exchange.go | 7 |  |  | w.Write([]byte(err.Error())) |
| FIM-REQUIRED | MEDIUM | templates/checkout.html | 1 |  |  | payment template advisory |
| GORM-ENCRYPT-OK | INFO | clean/gorm_encrypt_type/helper_encrypted/card_model.go | 3 |  |  | F-26 D-04 HelperEncryptedString Value() verified via 1-level recursion into EncryptPAN |
| GORM-ENCRYPT-OK | INFO | clean/gorm_encrypt_type/kms_encrypted/card_model.go | 3 |  |  | F-26 D-03 KMSEncryptedString Value() verified via KMS heuristic VaultKMSClient.Encrypt |
| GORM-ENCRYPT-OK | INFO | clean/gorm_encrypt_type/real_encrypted/card_model.go | 3 |  |  | F-26 D-02 SecureString Value() verified aes.NewCipher cipher.NewGCM |
| GORM-NO-ENCRYPT-HOOK | HIGH | internal/storage/postgres/model/fake_encrypt_model.go | 7 |  |  | F-26 D-06 FakeSecureToken type FakeEncryptedString Value body only base64 |
| GORM-NO-ENCRYPT-HOOK | HIGH | internal/storage/postgres/model/leaked.go | 3 |  |  | LeakedToken struct has no BeforeCreate/Encrypt |
| GORM-NO-ENCRYPT-HOOK | HIGH | internal/storage/postgres/model/token.go | 5 |  |  | Token struct has no encrypt hook |
| GORM-SENSITIVE-TAG | INFO | clean/gorm_encrypt_type/helper_encrypted/card_model.go | 5 |  |  | F-26 Number field with verified HelperEncryptedString custom type |
| GORM-SENSITIVE-TAG | INFO | clean/gorm_encrypt_type/kms_encrypted/card_model.go | 5 |  |  | F-26 Number field with verified KMSEncryptedString custom type |
| GORM-SENSITIVE-TAG | INFO | clean/gorm_encrypt_type/real_encrypted/card_model.go | 5 |  |  | F-26 Number field with verified SecureString custom type |
| GORM-SENSITIVE-TAG | INFO | internal/storage/postgres/model/card.go | 5 |  |  | clean Card model with BeforeCreate Encrypt hook |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/fake_encrypt_model.go | 9 |  |  | F-26 D-06 FakeSecureToken Number gorm column with unverified custom type |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/leaked.go | 6 | 3.5.1 |  | LeakedToken PAN gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/leaked.go | 5 | 3.3.1 |  | LeakedToken CVV gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/token.go | 8 | 3.5.1 |  | Token Number gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/token.go | 9 | 3.3.1 |  | Token CVV gorm column |
| GORM-SENSITIVE-TAG | MEDIUM | internal/storage/postgres/model/token.go | 11 |  |  | exp_month gorm column (defense-in-depth) |
| GORM-SENSITIVE-TAG | MEDIUM | internal/storage/postgres/model/token.go | 12 |  |  | exp_year gorm column (defense-in-depth) |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/central_abort_log.go | 30 | 6.2.4 |  | gap row P19: centralized Abort helper logs err.Error of wrapped chain |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/error_taint.go | 30 | 6.2.4 |  | gap row P5: AbortWithErrorLog logs err.Error of fmt.Errorf %w wrapping path param |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/errors_wrap_chain.go | 15 | 6.2.4 |  | gap row P21: errors-wrap chain final.Error logged after multi-level fmt.Errorf %w |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/multierror_wrap_log.go | 16 | 6.2.4 |  | gap row Phase21-U5: hashicorp/go-multierror Error string carries r.URL.Path through fmt.Errorf into slog.Error sink |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/struct_logger_field.go | 20 | 6.2.4 |  | gap row P12 err branch: h.log.Error read body failed err.Error |
| HTTP-INPUT-ERROR | HIGH | internal/http_input/stringer_token_errorf.go | 17 | 6.2.4 | 8.6.2 | case 3 format-verb-aware Stringer through fmt.Errorf %v auth-secret keyword |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/writer_writeback.go | 12 | 6.2.4 |  | gap row P22: raw path param written back to HTTP response writer |
| HTTP-INPUT-ERROR | MEDIUM | internal/http_input/zerolog_ctx_log.go | 16 | 6.2.4 |  | gap row Phase21-U3: zerolog log.Ctx finalizer Send emits Err of fmt.Errorf %w wrapping path param |
| HTTP-INPUT-LOG | HIGH | internal/http_input/apikey_uuid_branch_log.go | 14 | 10.2.1 | 8.6.2 | case 2 err branch raw apiKey before uuid.Parse to slog.Error value attr - auth-secret keyword high |
| HTTP-INPUT-LOG | HIGH | internal/http_input/apikey_uuid_branch_log.go | 18 | 10.2.1 | 8.6.2 | case 2 success branch post-validator UUID via api_key keyword - auth-secret override of sanitizer |
| HTTP-INPUT-LOG | HIGH | internal/http_input/bytes_buffer_body_log.go | 17 | 10.2.1 | 3.3.1, 6.2.4 | case 4 io.Copy ReverseFlow + bytes.Buffer.String method-projector + body-source override fires HIGH (origin c.Request.Body, identifier no keyword) |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/conditional_debug.go | 17 | 10.2.1 |  | gap row P7: conditional slog.Any inside if dbg branch |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/ctx_attrs_log.go | 15 | 10.2.1 |  | gap row P11: context-attached slog.With taint persists via ctx.Value |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/echo_path_log.go | 12 | 10.2.1 |  | gap row Phase21-U1: echo v4 c.Param to slog.String (cross-framework portability) |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/fiber_query_log.go | 10 | 10.2.1 |  | gap row Phase21-U2: fiber v2 c.Query into zerolog Event chain Str finalizer Msg (cross-framework + cross-logger portability) |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/header_log.go | 10 | 10.2.1 |  | gap row P2: net/http Header.Get to slog.String |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/json_struct_log.go | 20 | 10.2.1 |  | gap row P4: ShouldBindJSON struct then slog.Any whole struct |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/logrus_map_any_fields.go | 9 | 10.2.1 |  | gap row Phase21-U4: logrus.WithFields(map[string]any{...}) literal carrying URL.Path / Query / GetHeader |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/logrus_with_fields.go | 9 | 10.2.1 |  | gap row P16: logrus.WithFields sugar API with header / query / URL.Path |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/mask_bypass_err_path.go | 12 | 10.2.1 |  | gap row P13: error branch logs raw body (success branch is masked, no row) |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/mw_request_log.go | 14 | 10.2.1 |  | gap row P10: middleware access log baking URL.Path / headers via slog.Group |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/path_param_log.go | 11 | 10.2.1 |  | gap row P1: gin path param to slog.String |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/query_log.go | 10 | 10.2.1 |  | gap row P3: URL.Query.Get to slog.String |
| HTTP-INPUT-LOG | HIGH | internal/http_input/route_pan_promotion.go | 11 | 10.2.1 |  | gap row P18: keyword promotion via pan ident - severity HIGH per D-03 promotion path |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/slog_with_chain.go | 10 | 10.2.1 |  | gap row P15: slog.With binds path param; taint persists across With() chain |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/sprintf_intermediate.go | 11 | 10.2.1 |  | gap row P20: fmt.Sprintf intermediate defeats naive substring match |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/struct_logger_field.go | 24 | 10.2.1 |  | gap row P12: struct-embedded slog.Logger field log of raw body |
| HTTP-INPUT-LOG | CRITICAL | internal/http_input/validator_pan_value_log.go | 24 | 3.3.1 | 3.4.1, 8.6.2 | case 1 validator FieldError.Value any returns raw PAN/CVV - body decoded struct accessor through validator chain |
| HTTP-INPUT-LOG | MEDIUM | internal/http_input/validator_value_log.go | 26 | 10.2.1 |  | gap row P17: validator fieldErr.Value flows into details map then slog.Any |
| HTTP-INPUT-PANIC | MEDIUM | internal/http_input/gin_recovery_callback_log.go | 11 | 10.2.1 | 3.3.1 | case 5 gin.CustomRecoveryWithWriter callback recovered any auxiliary source |
| HTTP-INPUT-PANIC | MEDIUM | internal/http_input/defer_recovery_log.go | 13 | 10.2.1 |  | gap row P14: defer recover logs panic value via slog.Error |
| HTTP-INPUT-PANIC | MEDIUM | internal/http_input/panic_taint.go | 9 | 10.2.1 |  | gap row P6: literal panic of path param reaches gin.Recovery sink |
| META-CSP-ONLY | MEDIUM | templates/clean_checkout.html | 5 |  |  | meta CSP without HTTP header |
| META-CSP-ONLY | MEDIUM | templates/meta_only.html | 5 |  |  | meta CSP without HTTP header |
| META-CSP-UNSAFE | HIGH | templates/meta_unsafe.html | 5 |  |  | meta unsafe-inline directive |
| NONCE-MISSING | HIGH | templates/non_payment.html | 9 |  |  | non-payment inline script no nonce |
| NONCE-MISSING-PAYMENT | CRITICAL | templates/checkout.html | 13 |  |  | payment inline script no nonce |
| PAN-KEYWORD | INFO | clean/banking_struct/pure_banking.go | 5 |  |  | F-27 banking domain downgrade IBAN+BIC+RoutingNumber siblings tag banking_domain |
| PAN-KEYWORD | HIGH | internal/banking/mixed_pan_iban.go | 4 |  |  | F-27 defense-in-depth CVV PCI-scope sibling keeps HIGH |
| PAN-KEYWORD | INFO | internal/banking/mixed_pan_iban.go | 6 |  |  | CVV field taint SAD negative-evidence transit downgrade |
| PAN-KEYWORD | HIGH | internal/banking/mixed_pan_iban.go | 8 | 3.5.1 |  | CardNumber field in hybrid struct |
| PAN-KEYWORD | INFO | internal/billing/handler.go | 13 |  |  | transit-only PAN field still INFO |
| PAN-KEYWORD | INFO | internal/order/submit.go | 4 |  |  | CHD field + /order/ path, transit-only json tag |
| PAN-KEYWORD | INFO | internal/payment/core.go | 14 |  |  | tagless Number field still INFO |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/requests/tokenize.go | 4 |  |  | json-only DTO transit-only |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/requests/tokenize.go | 5 |  |  | json-only DTO transit-only |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/responses/exchange_token.go | 6 |  |  | response DTO transit-only |
| PAN-KEYWORD | INFO | internal/http_input/json_struct_log.go | 10 | 3.5.1 |  | CardNumber field in JSON DTO (transit-only taint downgrade) |
| PAN-KEYWORD | INFO | internal/http_input/json_struct_log.go | 11 | 3.3.1 | 3.3.1.2 | CVV field in JSON DTO (transit-only taint downgrade) |
| PAN-KEYWORD | INFO | internal/http_input/validator_value_log.go | 13 | 3.5.1 |  | CardNumber field in validator subscribe DTO (transit-only) |
| PAN-KEYWORD | INFO | internal/integration/stripe_client.go | 5 |  |  | F-28 D-03 adversarial guard: integration segment NOT excluded, transit-only struct downgraded by taint engine |
| PAN-KEYWORD | HIGH | internal/retention/entry.go | 10 |  |  | RED: incidental tagless Expiry field on Z9-Z12 scoring helper |
| PAN-KEYWORD | INFO | internal/service/tokens/model/model.go | 5 |  |  | negative evidence — tagless field |
| PAN-KEYWORD | HIGH | internal/service/tokens/model/model.go | 7 | 3.3.1 | 3.3.1.2 | tagless CVV escalated by struct sibling |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/leaked.go | 6 | 3.5.1 |  | PAN struct field |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/leaked.go | 5 | 3.3.1 | 3.3.1.2 | CVV struct field |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/token.go | 9 | 3.3.1 | 3.3.1.2 | gorm CVV column |
| PAN-KEYWORD | INFO | pkg/mastercard/models/card/card.go | 4 |  |  | json-only API model transit-only |
| PAN-KEYWORD | INFO | pkg/mastercard/models/card/card.go | 6 |  |  | json-only API model transit-only |
| PAN-LITERAL | MEDIUM | internal/auth/process.go | 6 |  |  | sample card literal in handler |
| PAN-LITERAL | MEDIUM | internal/http/handler/payment/charge.go | 6 |  |  | hardcoded sample card literal |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 4 |  |  | Visa Luhn-valid 4111111111111111 |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 5 |  |  | Mastercard Luhn-valid literal |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 6 |  |  | Amex Luhn-valid literal |
| PAN-LITERAL | MEDIUM | internal/util/cardops.go | 6 |  |  | sample card literal |
| PAN-LITERAL | MEDIUM | internal/util/cardproc.go | 6 |  |  | sample card literal |
| PAN-LOGGER | CRITICAL | internal/service/tokens/logging.go | 11 | 3.5.1 | 3.4.1, 10.2.1 | slog.Info with cardNumber ident arg |
| PAN-TYPE | MEDIUM | internal/banking/mixed_pan_iban.go | 4 |  |  | AccountNumber declared as string |
| PAN-TYPE | MEDIUM | internal/banking/mixed_pan_iban.go | 8 |  |  | CardNumber declared as string |
| PAN-TYPE | MEDIUM | internal/cache/keep_ttl.go | 9 |  |  | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/cache/no_expire_hset.go | 9 |  |  | cardNumber declared as string |
| PAN-TYPE | MEDIUM | internal/retention/entry.go | 10 |  |  | RED: incidental Expiry string declared on Z9-Z12 scoring helper |
| PAN-TYPE | MEDIUM | internal/service/tokens/model/model.go | 7 |  |  | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/service/tokens/store.go | 5 |  |  | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/leaked.go | 5 |  |  | Number declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/leaked.go | 6 |  |  | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/token.go | 9 |  |  | CVV declared as string |
| PAN-ZEROING | MEDIUM | internal/util/cardops.go | 6 |  |  | local cardNumber []byte without zeroing loop |
| RET-CONFIG-NO-TTL | HIGH | configs/cache.yaml | 5 |  |  | card_data block no ttl |
| RET-CONFIG-NO-TTL | INFO | clean/dev_compose/docker-compose.yml | 3 |  |  | card_data block no ttl dev path downgrade tag dev_path_skipped |
| RET-CONFIG-NO-TTL | HIGH | configs/docker-compose.yml | 3 |  |  | card_data block no ttl prod path stays HIGH adversarial |
| RET-DB-SENSITIVE-STORE | CRITICAL | internal/service/tokens/store.go | 6 |  |  | INSERT INTO sensitive_data(cvv) |
| RET-GORM-SENSITIVE-STORE | CRITICAL | internal/storage/postgres/tokens.go | 13 |  |  | gormDB.Create(cardToken) call site |
| RET-REDIS-KEEP-TTL | HIGH | internal/cache/keep_ttl.go | 10 |  |  | KeepTTL on sensitive key |
| RET-REDIS-NO-EXPIRE | HIGH | internal/cache/no_expire_hset.go | 10 |  |  | HSet on cardNumber no nearby Expire |
| RET-REDIS-NO-TTL | CRITICAL | internal/cache/sensitive_redis.go | 10 |  |  | rdb.Set(card:..., 0) TTL=0 |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/http/handler/payment/charge.go | 5 |  |  | range-zero loop after w.Write |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_elseif.go | 7 |  |  | RED: clear inside else-if branch body (walkStatements IfStmt.Else as IfStmt) |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_select.go | 10 |  |  | RED: clear inside SelectStmt CommClause body |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_switch.go | 7 |  |  | RED: clear inside SwitchStmt CaseClause body |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_typeswitch.go | 7 |  |  | RED: clear inside TypeSwitchStmt CaseClause body |
| RET-ZERO-BEFORE-AUTH | CRITICAL | internal/auth/process.go | 5 |  |  | range-zero loop before authorizeCard call |
| RET-ZERO-BEFORE-AUTH | CRITICAL | internal/payment/zeroing_init.go | 20 |  |  | if-init zeroing ( fixture) |
| RET-ZERO-DEFER-ONLY | HIGH | internal/util/cardproc.go | 5 |  |  | defer clearCard only, no explicit clear |
| SEC-CONNSTR | CRITICAL | configs/database.yaml | 2 |  |  | postgres://admin:secret123@db.local |
| SEC-CREDENTIAL-KEY | INFO | clean/examples/api-example.env.json | 0 |  |  | F-24 examples dir credential downgrades to INFO with TriageHint dev_path_examples_skipped |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/auth.toml | 0 |  |  | credential = "live_secret_xyz" |
| SEC-CREDENTIAL-KEY | INFO | configs/dev/local.env | 2 |  |  | DedicatedDev context downgrade |
| SEC-CREDENTIAL-KEY | INFO | configs/dev/local.env | 3 |  |  | DedicatedDev context downgrade |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/prod-api-key.json | 0 |  |  | F-24 adversarial production configs path stays CRITICAL |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/service.env | 1 |  |  | DATABASE_PASSWORD=supersecret |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/service.yaml | 5 |  |  | api_key sk_live_... |
| SEC-HIGH-ENTROPY | HIGH | configs/service.yaml | 5 |  |  | api_key high entropy literal |
| SEC-PREFIX | CRITICAL | configs/service.yaml | 5 |  |  | sk_live prefix detected |
| SQL-SENSITIVE-COLUMN | INFO | clean/migrations/20240101000000_add_legacy_card.sql | 3 |  |  | legacy_card.pan dropped in 20260101000000_drop_legacy_card tag column_dropped |
| SQL-SENSITIVE-COLUMN | HIGH | clean/readd_cycle/migrations/20240101000000_add_legacy_card.sql | 3 |  |  | readded_card.pan re-added after drop no downgrade |
| SQL-SENSITIVE-COLUMN | HIGH | clean/readd_cycle/migrations/20260301000000_readd_legacy_card.sql | 1 |  |  | ALTER TABLE ADD COLUMN pan — re-add column stays HIGH |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 4 | 3.5.1 |  | tokens.number column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 5 | 3.3.1 |  | tokens.cvv column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 15 | 3.5.1 |  | leaked_cards.pan column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 14 | 3.3.1 |  | leaked_cards.cvv column |
| SQL-TEXT-TYPE | INFO | clean/migrations/20240101000000_add_legacy_card.sql | 3 |  |  | legacy_card.pan dropped in 20260101000000_drop_legacy_card tag column_dropped |
| SQL-TEXT-TYPE | MEDIUM | clean/readd_cycle/migrations/20240101000000_add_legacy_card.sql | 3 |  |  | readded_card.pan re-added after drop no downgrade |
| SQL-TEXT-TYPE | MEDIUM | internal/storage/postgres/migrations/0001_init.sql | 14 |  |  | leaked_cards.number TEXT not BYTEA |
| SQL-TEXT-TYPE | MEDIUM | internal/storage/postgres/migrations/0001_init.sql | 15 |  |  | leaked_cards.cvv TEXT not BYTEA |
| SRI-MISSING | HIGH | templates/non_payment.html | 8 |  |  | non-payment cdn script no integrity |
| SRI-MISSING-PAYMENT | CRITICAL | templates/checkout.html | 12 |  |  | payment cdn script no integrity |
| TLS-INSECURE-SKIP-VERIFY | CRITICAL | pkg/visa/client.go | 11 |  |  | InsecureSkipVerify: true |
| TLS-MISSING-MIN-VERSION | HIGH | pkg/mastercard/client.go | 10 |  |  | empty tls.Config{} no MinVersion |
| TLS-MISSING-MIN-VERSION | HIGH | pkg/visa/client.go | 10 |  |  | tls.Config has no MinVersion |
| TLS-WEAK-CIPHER | CRITICAL | internal/http/legacy_client.go | 13 |  |  | TLS_RSA_WITH_RC4_128_SHA |
| TLS-WEAK-VERSION | CRITICAL | internal/http/legacy_client.go | 11 |  |  | MinVersion: tls.VersionTLS10 |

## Clean (must NOT be flagged HIGH or MEDIUM)

| File | Reason |
|------|--------|
| internal/storage/postgres/model/card.go | gorm Number field WITH BeforeCreate Encrypt hook (D-03 #1) |
| internal/testseed/constants.go | dev-context marker downgrades secrets to INFO (D-03 #6) |
| internal/testseed/fixtures_test.go | _test.go file excluded by default test exclusion (D-03 #7) |
| configs/dev/local.env | DedicatedDev context marker downgrades secrets to INFO (D-03 #10) |
| pkg/mastercard/models/card/card.go | json-only struct tag — transit downgrade (D-03 #12) |
| internal/http/handler/tokens/models/responses/exchange_token.go | response DTO json tag, transit-only (D-03 #2) |
| clean/dev_compose/docker-compose.yml | dev path prefix downgrades RET-CONFIG-NO-TTL to INFO (D-06) |
| clean/migrations/20240101000000_add_legacy_card.sql | column dropped in later migration — SQL-SENSITIVE-COLUMN and SQL-TEXT-TYPE downgraded to INFO (D-11) |
| clean/migrations/20260101000000_drop_legacy_card.sql | DROP COLUMN only, no sensitive column declared |
| clean/testutil/db_fixture.go | testutil path segment downgrades AUTH-HARDCODED-PWD to INFO (D-14) |
| clean/test_dir_exclusion/internal/test/e2e/mock_data.go | F-28: walker skips files under /test/ or /e2e/ segment at IncludeTests=false; file contains adversarial PAN and SEC-PREFIX that would fire at IncludeTests=true |
| clean/banking_struct/pure_banking.go | F-27 banking domain AccountNumber + IBAN/BIC/RoutingNumber downgrades PAN-KEYWORD to INFO |
| clean/crypto_filter_cases/header_const.go | F-25 Layer 2 header downgrade to INFO |
| clean/crypto_filter_cases/json_key.go | F-25 Layer 2 camelCase downgrade to INFO |
| clean/crypto_filter_cases/log_field.go | F-25 Layer 2 snake_case downgrade to INFO |
| clean/crypto_filter_cases/sentinel_error.go | F-25 Layer 1 AST sentinel error downgrade to INFO |
| clean/gorm_encrypt_type/real_encrypted/card_model.go | F-26 real crypto in Value() body — GORM-ENCRYPT-OK |
| clean/gorm_encrypt_type/helper_encrypted/card_model.go | F-26 helper recursion verified — GORM-ENCRYPT-OK |
| clean/gorm_encrypt_type/kms_encrypted/card_model.go | F-26 KMS client in Value() body — GORM-ENCRYPT-OK |
| clean/s2s_handler/stripe_hmac_webhook.go | B-21 T1 strong: hmac.Equal before json.Unmarshal — AUTH-MISSING-MFA downgrades to INFO |
| clean/webhook_signed/good_stripe_constructevent.go | B-22 T1 strong: webhook.ConstructEvent before json.Unmarshal — AUTH-WEBHOOK-VERIFIED INFO |
| clean/webhook_signed/good_hmac_generic.go | B-22 T1 strong: hmac.Equal before json.Unmarshal — AUTH-WEBHOOK-VERIFIED INFO |
| clean/webhook_signed/good_middleware_verified.go | B-22 middleware chain: VerifyWebhookSignatureMiddleware wrapper — AUTH-WEBHOOK-VERIFIED INFO |
| clean/webhook_signed/webhook_with_local_helper.go | B-22 1-level recursion: local verifyStripeSignature helper with hmac.Equal — AUTH-WEBHOOK-VERIFIED INFO |
| internal/http_input/uuid_post_validator_no_taint.go | case 6 negative differentiator: uuid.Parse sanitizer barrier + generic-ID class (widget_id) suppresses HTTP-INPUT-LOG emission per D-02 + D-03 |
| internal/http_input/request_id_log_no_taint.go | case 7 negative differentiator: own-generated request_id (crypto/rand) has no HTTP framework source, no taint, zero findings |

## SBOM Generation (Phase 20)

The SBOM contract verifies PCI DSS 6.3.2 (software inventory) coverage. Produced
by `sbomscanner.GenerateSBOM` on the fixture root; serialized via the CycloneDX
Go data model.

- Tool: `generate_sbom` MCP tool; direct Go API `sbomscanner.GenerateSBOM(ctx, path)`
- Format: CycloneDX v1.5 JSON (`bomFormat: "CycloneDX"`, `specVersion: "1.5"`)
- Component count: >=40 (fixture resolves to ~47 unique direct + transitive modules; 40 is the floor per CONTEXT R-05)
- Required fields per component: `name`, `version`, `purl`, `hashes` (SHA-256 from go.sum `h1:` lines); `licenses` best-effort per CONTEXT R-03
- Offline-mode contract: SBOM generation MUST succeed with network blocked as long as `$GOMODCACHE` is primed for the fixture's modules; unknown licenses surface as the `UNKNOWN-LICENSE` property entry per CONTEXT R-03
- PCI DSS 6.3.2 in `generate_compliance_report.requirement_status`: `PASS` on this fixture (go.mod present + parseable)
