CREATE TABLE tokens (
    id BIGSERIAL PRIMARY KEY,
    card_id TEXT NOT NULL,
    card_number BYTEA NOT NULL,
    cvv BYTEA NOT NULL,
    exp_month BIGINT,
    exp_year BIGINT,
    holder_name TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE leaked_cards (
    id BIGSERIAL PRIMARY KEY,
    cvv TEXT NOT NULL,
    pan TEXT NOT NULL,
    holder_name TEXT
);
