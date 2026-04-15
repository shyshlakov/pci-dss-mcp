-- +goose Up
-- Case 1: CREATE TABLE with sensitive text column AND a date column named expiry.
CREATE TABLE cards (
    id serial PRIMARY KEY,
    card_number text NOT NULL,
    expiry date
);

-- Case 3: ALTER TABLE ADD COLUMN for cvv stored as varchar(4).
ALTER TABLE users ADD COLUMN cvv varchar(4) NOT NULL;

-- Case 4: CREATE TABLE with sensitive column stored as bytea (encrypted at DB layer).
CREATE TABLE vaults (
    id serial PRIMARY KEY,
    pan bytea NOT NULL
);

-- Case 5: multi-statement with comments — only CREATE TABLE should be parsed.
-- +goose Down
DROP TABLE cards;
DROP TABLE vaults;
