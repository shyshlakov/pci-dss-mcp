CREATE TABLE legacy_card (
    id BIGSERIAL PRIMARY KEY,
    pan TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
