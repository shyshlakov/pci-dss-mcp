-- +goose Up
-- Case 2: token_hash is not a sensitive keyword, bytea type.
CREATE TABLE tokens (
    id serial PRIMARY KEY,
    token_hash bytea NOT NULL
);

-- Plain users table with email + name — no sensitive keywords.
CREATE TABLE users (
    id serial PRIMARY KEY,
    email text NOT NULL,
    name varchar(255)
);

-- +goose Down
DROP TABLE tokens;
DROP TABLE users;
