---
fixture_version: 1.5
last_updated: 2025-01-15
phase: n/a
plan: n/a
total_intentional_violations: 130
total_clean_patterns: 12
total_rules_covered: 54
expected_summary:
 critical: 42
 high: 80
 medium: 26
 low: 0
 info: 35
expected_active: 151
expected_total_findings: 185
rules_coverage:
 panscanner: [PAN-KEYWORD, PAN-TYPE, PAN-LITERAL, PAN-LOGGER, PAN-ZEROING]
 cryptoscanner: [CRYPTO-WEAK-HASH, CRYPTO-HARDCODED-KEY, CRYPTO-PLAIN-HTTP]
 tlsscanner: [TLS-INSECURE-SKIP-VERIFY, TLS-MISSING-MIN-VERSION, TLS-WEAK-VERSION, TLS-WEAK-CIPHER]
 secretscanner: [SEC-PREFIX, SEC-HIGH-ENTROPY, SEC-CONNSTR, SEC-CREDENTIAL-KEY]
 errorscanner: [ERR-LEAK-DIRECT, ERR-LEAK-FORMAT, ERR-LEAK-WRITE, ERR-LEAK-ENCODE]
 authscanner: [AUTH-HARDCODED-PWD, AUTH-WEAK-POLICY, AUTH-MISSING-MFA, AUTH-BYTE-COUNT]
 auditscanner: [AUDIT-NO-LOG, AUDIT-UNSTRUCTURED, AUDIT-LOG-OK]
 retentionscanner: [RET-DB-SENSITIVE-STORE, RET-GORM-SENSITIVE-STORE, RET-REDIS-NO-TTL, RET-REDIS-KEEP-TTL, RET-REDIS-NO-EXPIRE, RET-CONFIG-NO-TTL, RET-ZERO-BEFORE-AUTH, RET-ZERO-AFTER-RESPONSE, RET-ZERO-DEFER-ONLY]
 scriptscanner: [CSP-MISSING, CSP-OK, CSP-UNSAFE-INLINE, CSP-UNSAFE-EVAL, CSP-NO-SCRIPT-SRC, CSP-VALUE-UNANALYZABLE, META-CSP-ONLY, META-CSP-UNSAFE, SRI-MISSING, SRI-MISSING-PAYMENT, NONCE-MISSING, NONCE-MISSING-PAYMENT, FIM-REQUIRED]
 depscanner: [DEP-VULN]
 sqlscanner: [SQL-SENSITIVE-COLUMN, SQL-TEXT-TYPE, GORM-SENSITIVE-TAG, GORM-NO-ENCRYPT-HOOK]
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
| CRITICAL | 41 |
| HIGH | 80 |
| MEDIUM | 25 |
| LOW | 0 |
| INFO | 35 |

## Violations

| Rule ID | Severity | File | Line | Notes |
|---------|----------|------|------|-------|
| AUDIT-LOG-OK | INFO | internal/http/handler/tokens/tokenize.go | 11 | logrus structured fields PCI 10.2.1 partial coverage |
| AUDIT-NO-LOG | CRITICAL | internal/auth/process.go | 5 | AuthorizeCharge handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/callback/mastercard.go | 8 | S2S callback handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/checkout.go | 8 | RenderCheckout no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/dynamic.go | 8 | RenderCheckoutDynamic handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/eval.go | 8 | RenderCheckoutEval handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/inline.go | 8 | RenderCheckoutInline handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/checkout/noscript.go | 8 | RenderCheckoutNoScript handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/payment/charge.go | 5 | charge handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/payment/clean.go | 8 | RenderCheckoutClean handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/tokens/exchange.go | 5 | TokenizeCardExchange handler no log calls |
| AUDIT-NO-LOG | CRITICAL | internal/http/handler/tokens/metadata.go | 8 | CardMetadata handler no log calls |
| AUDIT-NO-LOG | HIGH | internal/billing/encode_map.go | 19 | EncodeHandler no log calls after fixture-shortcut removal |
| AUDIT-NO-LOG | HIGH | internal/payment/zeroing_init.go | 20 | incidental tier-2 AUDIT-NO-LOG on fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_elseif.go | 7 | RED: incidental tier-2 AUDIT-NO-LOG on Z9 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_select.go | 10 | RED: incidental tier-2 AUDIT-NO-LOG on Z12 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_switch.go | 7 | RED: incidental tier-2 AUDIT-NO-LOG on Z10 fixture |
| AUDIT-NO-LOG | HIGH | internal/retention/zeroing_typeswitch.go | 7 | RED: incidental tier-2 AUDIT-NO-LOG on Z11 fixture |
| AUDIT-NO-LOG | HIGH | internal/tokens/delegation/delegating.go | 19 | RED: incidental tier-2 AUDIT-NO-LOG on delegation-only Wrapper.ServeHTTP (stays flagged after because audit scanner is not in scope of this plan) |
| AUDIT-NO-LOG | CRITICAL | internal/util/cardproc.go | 5 | ProcessCardBuffer handler no log calls |
| AUDIT-UNSTRUCTURED | CRITICAL | internal/http/handler/tokens/detokenize.go | 8 | fmt.Println logging only |
| AUDIT-UNSTRUCTURED | HIGH | internal/billing/handler.go | 16 | tier-2 HIGH after fixture-shortcut removal |
| AUDIT-UNSTRUCTURED | HIGH | internal/exchange/handler.go | 10 | tier-2 HIGH after fixture-shortcut removal |
| AUDIT-UNSTRUCTURED | HIGH | internal/payment/core.go | 19 | tier-2 HIGH after fixture-shortcut removal |
| AUTH-BYTE-COUNT | MEDIUM | internal/auth/policy.go | 12 | len(password) byte count check |
| AUTH-HARDCODED-PWD | INFO | clean/testutil/db_fixture.go | 3 | testutil helper hardcoded password testutil_exclusion downgrade |
| AUTH-HARDCODED-PWD | CRITICAL | internal/auth/admin.go | 3 | const AdminPassword = "admin123" |
| AUTH-HARDCODED-PWD | CRITICAL | internal/payment/hardcoded_admin.go | 3 | prod path hardcoded admin password stays CRITICAL adversarial |
| AUTH-MISSING-MFA | HIGH | internal/auth/process.go | 5 | AuthorizeCharge handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/billing/encode_map.go | 19 | EncodeHandler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/billing/handler.go | 16 | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/exchange/handler.go | 10 | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/http/handler.go | 10 | router has no MFA middleware |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/callback/mastercard.go | 8 | callback handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/checkout.go | 8 | checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/dynamic.go | 8 | dynamic checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/eval.go | 8 | eval checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/inline.go | 8 | inline checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/checkout/noscript.go | 8 | noscript checkout handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/payment/charge.go | 5 | charge handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/payment/clean.go | 8 | RenderCheckoutClean handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/detokenize.go | 8 | detokenize handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/exchange.go | 5 | TokenizeCardExchange handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/metadata.go | 8 | CardMetadata handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/http/handler/tokens/tokenize.go | 11 | tokenize handler no MFA |
| AUTH-MISSING-MFA | HIGH | internal/payment/core.go | 19 | abstract handler no MFA gate after fixture-shortcut removal |
| AUTH-MISSING-MFA | HIGH | internal/payment/zeroing_init.go | 20 | incidental AUTH-MISSING-MFA on fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_elseif.go | 7 | RED: incidental AUTH-MISSING-MFA on Z9 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_select.go | 10 | RED: incidental AUTH-MISSING-MFA on Z12 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_switch.go | 7 | RED: incidental AUTH-MISSING-MFA on Z10 fixture |
| AUTH-MISSING-MFA | HIGH | internal/retention/zeroing_typeswitch.go | 7 | RED: incidental AUTH-MISSING-MFA on Z11 fixture |
| AUTH-MISSING-MFA | HIGH | internal/util/cardproc.go | 5 | ProcessCardBuffer handler no MFA |
| AUTH-WEAK-POLICY | CRITICAL | internal/auth/policy.go | 12 | MinPasswordLength below PCI 8.3.6 |
| CRYPTO-HARDCODED-KEY | CRITICAL | internal/auth/admin.go | 3 | hardcoded admin secret |
| CRYPTO-HARDCODED-KEY | HIGH | internal/auth/process.go | 6 | hardcoded sample literal in handler |
| CRYPTO-HARDCODED-KEY | CRITICAL | internal/crypto/keys.go | 3 | AESKey constant 32 hex chars |
| CRYPTO-HARDCODED-KEY | HIGH | internal/http/handler/payment/charge.go | 6 | hardcoded key inside payment handler |
| CRYPTO-HARDCODED-KEY | INFO | internal/testseed/constants.go | 3 | dev-context marker downgrades to INFO |
| CRYPTO-HARDCODED-KEY | HIGH | internal/util/cardops.go | 6 | hardcoded sample literal |
| CRYPTO-HARDCODED-KEY | HIGH | internal/util/cardproc.go | 6 | hardcoded sample literal |
| CRYPTO-PLAIN-HTTP | CRITICAL | internal/http/client.go | 8 | http://api.payment.example/charge |
| CRYPTO-WEAK-HASH | CRITICAL | internal/crypto/hash.go | 6 | md5.Sum on password input |
| CSP-MISSING | INFO | internal/auth/process.go | 5 | non-HTML payment handler informational note |
| CSP-MISSING | INFO | internal/billing/handler.go | 16 | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | INFO | internal/exchange/handler.go | 10 | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | HIGH | internal/http/handler/checkout/checkout.go | 8 | RenderCheckout no Content-Security-Policy header |
| CSP-MISSING | INFO | internal/http/handler/payment/charge.go | 5 | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/detokenize.go | 8 | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/exchange.go | 5 | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/http/handler/tokens/tokenize.go | 11 | non-HTML handler informational note |
| CSP-MISSING | INFO | internal/payment/core.go | 19 | non-HTML handler informational note after fixture-shortcut removal |
| CSP-MISSING | INFO | internal/util/cardproc.go | 5 | non-HTML handler informational note |
| CSP-NO-SCRIPT-SRC | HIGH | internal/http/handler/checkout/noscript.go | 8 | CSP missing script-src and default-src |
| CSP-OK | INFO | internal/http/handler/payment/clean.go | 8 | verified valid CSP header set |
| CSP-UNSAFE-EVAL | HIGH | internal/http/handler/checkout/eval.go | 8 | script-src 'unsafe-eval' literal |
| CSP-UNSAFE-INLINE | HIGH | internal/http/handler/checkout/inline.go | 8 | script-src 'unsafe-inline' literal |
| CSP-VALUE-UNANALYZABLE | INFO | internal/http/handler/checkout/dynamic.go | 8 | CSP value sourced from variable |
| DEP-VULN | HIGH | go.mod | 7 | go-jose/v4 v4.1.3 advisory |
| ERR-LEAK-DIRECT | CRITICAL | internal/http/handler/tokens/tokenize.go | 21 | http.Error(w, err.Error(), 500) |
| ERR-LEAK-ENCODE | CRITICAL | internal/billing/encode_map.go | 22 | map-literal err leak ( fixture) |
| ERR-LEAK-ENCODE | CRITICAL | internal/http/handler/tokens/metadata.go | 11 | json.NewEncoder(w).Encode(err) |
| ERR-LEAK-FORMAT | HIGH | internal/billing/handler.go | 19 | abstract HandleRequest name, /billing/ path + PAN field, multi-signal |
| ERR-LEAK-FORMAT | HIGH | internal/exchange/handler.go | 12 | abstract Execute name, go-jose SDK import, signal 3 |
| ERR-LEAK-FORMAT | HIGH | internal/http/handler/tokens/detokenize.go | 10 | fmt.Fprintf %v err |
| ERR-LEAK-FORMAT | HIGH | internal/payment/core.go | 19 | abstract Execute name, /payment/ path + *Card param, signal 2 + 4 |
| ERR-LEAK-WRITE | CRITICAL | internal/http/handler/tokens/exchange.go | 7 | w.Write([]byte(err.Error())) |
| FIM-REQUIRED | MEDIUM | templates/checkout.html | 1 | payment template advisory |
| GORM-NO-ENCRYPT-HOOK | HIGH | internal/storage/postgres/model/leaked.go | 3 | LeakedToken struct has no BeforeCreate/Encrypt |
| GORM-NO-ENCRYPT-HOOK | HIGH | internal/storage/postgres/model/token.go | 5 | Token struct has no encrypt hook |
| GORM-SENSITIVE-TAG | INFO | internal/storage/postgres/model/card.go | 5 | clean Card model with BeforeCreate Encrypt hook |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/leaked.go | 5 | LeakedToken Number gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/leaked.go | 6 | LeakedToken CVV gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/token.go | 8 | Token Number gorm column |
| GORM-SENSITIVE-TAG | HIGH | internal/storage/postgres/model/token.go | 9 | Token CVV gorm column |
| GORM-SENSITIVE-TAG | MEDIUM | internal/storage/postgres/model/token.go | 11 | exp_month gorm column (defense-in-depth) |
| GORM-SENSITIVE-TAG | MEDIUM | internal/storage/postgres/model/token.go | 12 | exp_year gorm column (defense-in-depth) |
| META-CSP-ONLY | MEDIUM | templates/clean_checkout.html | 5 | meta CSP without HTTP header |
| META-CSP-ONLY | MEDIUM | templates/meta_only.html | 5 | meta CSP without HTTP header |
| META-CSP-UNSAFE | HIGH | templates/meta_unsafe.html | 5 | meta unsafe-inline directive |
| NONCE-MISSING | HIGH | templates/non_payment.html | 9 | non-payment inline script no nonce |
| NONCE-MISSING-PAYMENT | CRITICAL | templates/checkout.html | 13 | payment inline script no nonce |
| PAN-KEYWORD | INFO | internal/billing/handler.go | 15 | transit-only PAN field still INFO |
| PAN-KEYWORD | INFO | internal/order/submit.go | 6 | CHD field + /order/ path, transit-only json tag |
| PAN-KEYWORD | INFO | internal/payment/core.go | 13 | tagless Number field still INFO |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/requests/tokenize.go | 4 | json-only DTO transit-only |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/requests/tokenize.go | 5 | json-only DTO transit-only |
| PAN-KEYWORD | INFO | internal/http/handler/tokens/models/responses/exchange_token.go | 6 | response DTO transit-only |
| PAN-KEYWORD | CRITICAL | internal/integration/stripe_client.go | 5 | F-28 D-03 adversarial guard: integration segment NOT excluded, production integration code stays walked |
| PAN-KEYWORD | HIGH | internal/retention/entry.go | 10 | RED: incidental tagless Expiry field on Z9-Z12 scoring helper |
| PAN-KEYWORD | INFO | internal/service/tokens/model/model.go | 5 | negative evidence — tagless field |
| PAN-KEYWORD | HIGH | internal/service/tokens/model/model.go | 7 | tagless CVV escalated by struct sibling |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/leaked.go | 5 | gorm Number column |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/leaked.go | 6 | gorm CVV column |
| PAN-KEYWORD | HIGH | internal/storage/postgres/model/token.go | 9 | gorm CVV column |
| PAN-KEYWORD | INFO | pkg/mastercard/models/card/card.go | 4 | json-only API model transit-only |
| PAN-KEYWORD | INFO | pkg/mastercard/models/card/card.go | 6 | json-only API model transit-only |
| PAN-LITERAL | MEDIUM | internal/auth/process.go | 6 | sample card literal in handler |
| PAN-LITERAL | MEDIUM | internal/http/handler/payment/charge.go | 6 | hardcoded sample card literal |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 4 | Visa Luhn-valid 4111111111111111 |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 5 | Mastercard Luhn-valid literal |
| PAN-LITERAL | MEDIUM | internal/testseed/data/seed.go | 6 | Amex Luhn-valid literal |
| PAN-LITERAL | MEDIUM | internal/util/cardops.go | 6 | sample card literal |
| PAN-LITERAL | MEDIUM | internal/util/cardproc.go | 6 | sample card literal |
| PAN-LOGGER | CRITICAL | internal/service/tokens/logging.go | 11 | slog.Info with cardNumber ident arg |
| PAN-TYPE | MEDIUM | internal/cache/keep_ttl.go | 9 | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/cache/no_expire_hset.go | 9 | cardNumber declared as string |
| PAN-TYPE | MEDIUM | internal/integration/stripe_client.go | 5 | F-28 D-03 adversarial guard: CardNumber string field in production integration stays walked |
| PAN-TYPE | MEDIUM | internal/retention/entry.go | 10 | RED: incidental Expiry string declared on Z9-Z12 scoring helper |
| PAN-TYPE | MEDIUM | internal/service/tokens/model/model.go | 7 | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/service/tokens/store.go | 5 | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/leaked.go | 5 | Number declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/leaked.go | 6 | CVV declared as string |
| PAN-TYPE | MEDIUM | internal/storage/postgres/model/token.go | 9 | CVV declared as string |
| PAN-ZEROING | MEDIUM | internal/util/cardops.go | 6 | local cardNumber []byte without zeroing loop |
| RET-CONFIG-NO-TTL | HIGH | configs/cache.yaml | 5 | card_data block no ttl |
| RET-CONFIG-NO-TTL | INFO | clean/dev_compose/docker-compose.yml | 3 | card_data block no ttl dev path downgrade tag dev_path_skipped |
| RET-CONFIG-NO-TTL | HIGH | configs/docker-compose.yml | 3 | card_data block no ttl prod path stays HIGH adversarial |
| RET-DB-SENSITIVE-STORE | CRITICAL | internal/service/tokens/store.go | 6 | INSERT INTO sensitive_data(cvv) |
| RET-GORM-SENSITIVE-STORE | CRITICAL | internal/storage/postgres/tokens.go | 13 | gormDB.Create(cardToken) call site |
| RET-REDIS-KEEP-TTL | HIGH | internal/cache/keep_ttl.go | 10 | KeepTTL on sensitive key |
| RET-REDIS-NO-EXPIRE | HIGH | internal/cache/no_expire_hset.go | 10 | HSet on cardNumber no nearby Expire |
| RET-REDIS-NO-TTL | CRITICAL | internal/cache/sensitive_redis.go | 10 | rdb.Set(card:..., 0) TTL=0 |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/http/handler/payment/charge.go | 5 | range-zero loop after w.Write |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_elseif.go | 7 | RED: clear inside else-if branch body (walkStatements IfStmt.Else as IfStmt) |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_select.go | 10 | RED: clear inside SelectStmt CommClause body |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_switch.go | 7 | RED: clear inside SwitchStmt CaseClause body |
| RET-ZERO-AFTER-RESPONSE | HIGH | internal/retention/zeroing_typeswitch.go | 7 | RED: clear inside TypeSwitchStmt CaseClause body |
| RET-ZERO-BEFORE-AUTH | CRITICAL | internal/auth/process.go | 5 | range-zero loop before authorizeCard call |
| RET-ZERO-BEFORE-AUTH | CRITICAL | internal/payment/zeroing_init.go | 20 | if-init zeroing ( fixture) |
| RET-ZERO-DEFER-ONLY | HIGH | internal/util/cardproc.go | 5 | defer clearCard only, no explicit clear |
| SEC-CONNSTR | CRITICAL | configs/database.yaml | 2 | postgres://admin:secret123@db.local |
| SEC-CREDENTIAL-KEY | INFO | clean/examples/api-example.env.json | 0 | F-24 examples dir credential downgrades to INFO with TriageHint dev_path_examples_skipped |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/auth.toml | 0 | credential = "live_secret_xyz" |
| SEC-CREDENTIAL-KEY | INFO | configs/dev/local.env | 2 | DedicatedDev context downgrade |
| SEC-CREDENTIAL-KEY | INFO | configs/dev/local.env | 3 | DedicatedDev context downgrade |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/prod-api-key.json | 0 | F-24 adversarial production configs path stays CRITICAL |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/service.env | 1 | DATABASE_PASSWORD=supersecret |
| SEC-CREDENTIAL-KEY | CRITICAL | configs/service.yaml | 5 | api_key sk_live_... |
| SEC-HIGH-ENTROPY | HIGH | configs/service.yaml | 5 | api_key high entropy literal |
| SEC-PREFIX | CRITICAL | configs/service.yaml | 5 | sk_live prefix detected |
| SQL-SENSITIVE-COLUMN | INFO | clean/migrations/20240101000000_add_legacy_card.sql | 3 | legacy_card.pan dropped in 20260101000000_drop_legacy_card tag column_dropped |
| SQL-SENSITIVE-COLUMN | HIGH | clean/readd_cycle/migrations/20240101000000_add_legacy_card.sql | 3 | readded_card.pan re-added after drop no downgrade |
| SQL-SENSITIVE-COLUMN | HIGH | clean/readd_cycle/migrations/20260301000000_readd_legacy_card.sql | 1 | ALTER TABLE ADD COLUMN pan — re-add column stays HIGH |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 4 | tokens.number column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 5 | tokens.cvv column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 14 | leaked_cards.number column |
| SQL-SENSITIVE-COLUMN | HIGH | internal/storage/postgres/migrations/0001_init.sql | 15 | leaked_cards.cvv column |
| SQL-TEXT-TYPE | INFO | clean/migrations/20240101000000_add_legacy_card.sql | 3 | legacy_card.pan dropped in 20260101000000_drop_legacy_card tag column_dropped |
| SQL-TEXT-TYPE | MEDIUM | clean/readd_cycle/migrations/20240101000000_add_legacy_card.sql | 3 | readded_card.pan re-added after drop no downgrade |
| SQL-TEXT-TYPE | MEDIUM | internal/storage/postgres/migrations/0001_init.sql | 14 | leaked_cards.number TEXT not BYTEA |
| SQL-TEXT-TYPE | MEDIUM | internal/storage/postgres/migrations/0001_init.sql | 15 | leaked_cards.cvv TEXT not BYTEA |
| SRI-MISSING | HIGH | templates/non_payment.html | 8 | non-payment cdn script no integrity |
| SRI-MISSING-PAYMENT | CRITICAL | templates/checkout.html | 12 | payment cdn script no integrity |
| TLS-INSECURE-SKIP-VERIFY | CRITICAL | pkg/visa/client.go | 11 | InsecureSkipVerify: true |
| TLS-MISSING-MIN-VERSION | HIGH | pkg/mastercard/client.go | 10 | empty tls.Config{} no MinVersion |
| TLS-MISSING-MIN-VERSION | HIGH | pkg/visa/client.go | 10 | tls.Config has no MinVersion |
| TLS-WEAK-CIPHER | CRITICAL | internal/http/legacy_client.go | 13 | TLS_RSA_WITH_RC4_128_SHA |
| TLS-WEAK-VERSION | CRITICAL | internal/http/legacy_client.go | 11 | MinVersion: tls.VersionTLS10 |

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
