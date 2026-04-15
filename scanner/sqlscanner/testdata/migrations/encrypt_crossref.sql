-- Fixture for D-02 cross-reference test: cards table with PAN as text (not bytea).
-- SQL scanner alone flags number/exp_month/exp_year as HIGH.
-- Cross-ref with Go struct (card_encrypt_crossref.go) should:
--   - Downgrade number to INFO (Go encrypt hook for Number)
--   - Suppress exp_month/exp_year (Go-level PAN encryption detected)

CREATE TABLE cards (
    id uuid PRIMARY KEY,
    number text,
    exp_month bigint,
    exp_year bigint,
    last4 varchar(4)
);
