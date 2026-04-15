-- Context-aware SQL fixture for an earlier release Plan 02 tests.
-- Cards table: number/exp_month/exp_year are sensitive in card context.
-- Users table: number/account are NOT sensitive (non-card context).

CREATE TABLE "cards" (
    id uuid PRIMARY KEY,
    number text NULL,
    exp_month bigint,
    exp_year bigint,
    last4 varchar(4),
    mask varchar(19),
    hash text NOT NULL
);

CREATE TABLE "users" (
    id uuid PRIMARY KEY,
    number varchar(50),
    account varchar(100),
    email text NOT NULL
);

ALTER TABLE "cards" ADD COLUMN verification_code text;
