-- PayBridge v1 schema (SQLite dialect; Postgres notes inline).
-- Timestamps: ISO-8601 TEXT in UTC (PG: timestamptz). Money: INTEGER minor units + CHAR(3).
-- IDs: prefixed ULIDs, generated app-side.

CREATE TABLE merchants (
    id          TEXT PRIMARY KEY,                -- mch_01K…
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  TEXT NOT NULL
);

CREATE TABLE merchant_api_keys (
    id          TEXT PRIMARY KEY,                -- key_01K…
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    prefix      TEXT NOT NULL,                   -- first 12 chars for lookup, e.g. pb_sk_test_ac
    key_hash    TEXT NOT NULL,                   -- sha256 hex of the full secret key
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);
CREATE INDEX idx_api_keys_prefix ON merchant_api_keys (prefix);

CREATE TABLE merchant_payment_methods (
    id                 TEXT PRIMARY KEY,         -- mpm_01K…
    merchant_id        TEXT NOT NULL REFERENCES merchants(id),
    provider           TEXT NOT NULL CHECK (provider IN ('telebirr', 'cbebirr', 'mpesa', 'awash')),
    display_name       TEXT NOT NULL,            -- shown on the hosted checkout, e.g. "Telebirr"
    account_identifier TEXT NOT NULL,            -- receiving wallet, e.g. +251900000000 (exact match target)
    instructions       TEXT NOT NULL,            -- numbered steps shown to the customer
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at         TEXT NOT NULL
);
CREATE INDEX idx_payment_methods_merchant ON merchant_payment_methods (merchant_id, status);

CREATE TABLE webhook_endpoints (
    id          TEXT PRIMARY KEY,                -- wh_01K…
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,                   -- HMAC key, shown once at creation
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  TEXT NOT NULL
);

CREATE TABLE checkouts (
    id                 TEXT PRIMARY KEY,         -- chk_01K…
    merchant_id        TEXT NOT NULL REFERENCES merchants(id),
    reference          TEXT NOT NULL,            -- merchant's own order id, e.g. ORDER-12345
    amount_minor       INTEGER NOT NULL CHECK (amount_minor > 0),
    currency           TEXT NOT NULL CHECK (currency = 'ETB'),          -- v1: ETB only
    status             TEXT NOT NULL DEFAULT 'created'
                       CHECK (status IN ('created', 'pending', 'succeeded', 'failed', 'expired')),
    customer_name      TEXT,
    customer_email     TEXT,
    return_url         TEXT,
    selected_method_id TEXT REFERENCES merchant_payment_methods(id),
    expires_at         TEXT NOT NULL,
    paid_at            TEXT,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX idx_checkouts_merchant ON checkouts (merchant_id, created_at);
CREATE INDEX idx_checkouts_expiry   ON checkouts (status, expires_at);

CREATE TABLE checkout_items (
    id               TEXT PRIMARY KEY,
    checkout_id      TEXT NOT NULL REFERENCES checkouts(id),
    name             TEXT NOT NULL,
    quantity         INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_minor INTEGER NOT NULL CHECK (unit_price_minor >= 0)
);
CREATE INDEX idx_checkout_items_checkout ON checkout_items (checkout_id);

-- Audit trail of every public verify call (also drives rate limiting).
CREATE TABLE payment_attempts (
    id                    TEXT PRIMARY KEY,     -- att_01K…
    checkout_id           TEXT NOT NULL REFERENCES checkouts(id),
    transaction_reference TEXT NOT NULL,
    outcome               TEXT NOT NULL CHECK (outcome IN
                          ('succeeded', 'transaction_not_found', 'transaction_not_successful',
                           'transaction_too_old', 'amount_mismatch', 'currency_mismatch',
                           'recipient_mismatch', 'transaction_already_used',
                           'verification_service_error')),
    detail                TEXT,                 -- e.g. expected vs actual amount
    created_at            TEXT NOT NULL
);
CREATE INDEX idx_attempts_checkout ON payment_attempts (checkout_id, created_at);

-- One row per method-selection/verify run; transaction attached on success.
CREATE TABLE payments (
    id          TEXT PRIMARY KEY,                -- pay_01K…
    checkout_id TEXT NOT NULL REFERENCES checkouts(id),
    method_id   TEXT NOT NULL REFERENCES merchant_payment_methods(id),
    provider    TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated', 'succeeded', 'failed')),
    amount_minor INTEGER NOT NULL,
    currency    TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_payments_checkout ON payments (checkout_id);

-- Only inserted after full validation passes. The UNIQUE constraint is the
-- transaction-reuse guard: one real wallet transaction can pay one checkout.
CREATE TABLE transactions (
    id                    TEXT PRIMARY KEY,     -- txn_01K…
    payment_id            TEXT NOT NULL REFERENCES payments(id),
    provider              TEXT NOT NULL,
    transaction_reference TEXT NOT NULL,
    amount_minor          INTEGER NOT NULL,     -- as reported by the verification service
    currency              TEXT NOT NULL,
    recipient             TEXT NOT NULL,        -- receiving wallet, exact
    occurred_at           TEXT NOT NULL,        -- original transaction time at the provider
    raw_response          TEXT,                 -- verifier JSON, for audit/disputes
    created_at            TEXT NOT NULL,
    UNIQUE (provider, transaction_reference)
);

-- Transactional outbox: committed in the same DB transaction as the state change.
CREATE TABLE outbox_messages (
    id             TEXT PRIMARY KEY,             -- evt_01K… (this is the webhook eventId)
    event_type     TEXT NOT NULL,                -- 'checkout.payment_succeeded'
    aggregate_id   TEXT NOT NULL,                -- checkout id
    payload        TEXT NOT NULL,                -- final webhook JSON body
    status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error     TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX idx_outbox_due ON outbox_messages (status, next_attempt_at);

-- One row per (event, endpoint); records every HTTP attempt for support.
CREATE TABLE webhook_deliveries (
    id              TEXT PRIMARY KEY,            -- whd_01K…
    outbox_id       TEXT NOT NULL REFERENCES outbox_messages(id),
    endpoint_id     TEXT NOT NULL REFERENCES webhook_endpoints(id),
    attempt_no      INTEGER NOT NULL,
    status_code     INTEGER,                     -- NULL on timeout/connection error
    error           TEXT,
    duration_ms     INTEGER,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_deliveries_outbox ON webhook_deliveries (outbox_id, attempt_no);

-- Idempotency-Key replay protection for POST /api/v1/checkouts.
CREATE TABLE idempotency_keys (
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    key         TEXT NOT NULL,
    checkout_id TEXT NOT NULL REFERENCES checkouts(id),
    created_at  TEXT NOT NULL,
    PRIMARY KEY (merchant_id, key)
);

-- ------------------------------------------------------------------
-- Dev seed: merchant "Acme Tickets" (see DESIGN.md §12). PG note:
-- keep DDL identical; swap TEXT timestamps for timestamptz and add
-- SELECT … FOR UPDATE SKIP LOCKED on outbox claiming in the worker.
-- ------------------------------------------------------------------
