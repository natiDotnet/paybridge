-- PayBridge v1 schema (SQLite dialect). Timestamps: ISO-8601 TEXT in UTC.
-- Money: INTEGER minor units + CHAR(3). IDs: prefixed ULIDs, generated app-side.

CREATE TABLE merchants (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  TEXT NOT NULL
);

CREATE TABLE merchant_api_keys (
    id          TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    prefix      TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);
CREATE INDEX idx_api_keys_prefix ON merchant_api_keys (prefix);

CREATE TABLE merchant_payment_methods (
    id                 TEXT PRIMARY KEY,
    merchant_id        TEXT NOT NULL REFERENCES merchants(id),
    provider           TEXT NOT NULL CHECK (provider IN ('telebirr', 'cbebirr', 'mpesa', 'awash')),
    display_name       TEXT NOT NULL,
    account_identifier TEXT NOT NULL,
    instructions       TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at         TEXT NOT NULL
);
CREATE INDEX idx_payment_methods_merchant ON merchant_payment_methods (merchant_id, status);

CREATE TABLE webhook_endpoints (
    id          TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at  TEXT NOT NULL
);

CREATE TABLE checkouts (
    id                 TEXT PRIMARY KEY,
    merchant_id        TEXT NOT NULL REFERENCES merchants(id),
    reference          TEXT NOT NULL,
    amount_minor       INTEGER NOT NULL CHECK (amount_minor > 0),
    currency           TEXT NOT NULL CHECK (currency = 'ETB'),
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

CREATE TABLE payment_attempts (
    id                    TEXT PRIMARY KEY,
    checkout_id           TEXT NOT NULL REFERENCES checkouts(id),
    transaction_reference TEXT NOT NULL,
    outcome               TEXT NOT NULL CHECK (outcome IN
                          ('succeeded', 'transaction_not_found', 'transaction_not_successful',
                           'transaction_too_old', 'amount_mismatch', 'currency_mismatch',
                           'recipient_mismatch', 'transaction_already_used',
                           'verification_service_error')),
    detail                TEXT,
    created_at            TEXT NOT NULL
);
CREATE INDEX idx_attempts_checkout ON payment_attempts (checkout_id, created_at);

CREATE TABLE payments (
    id           TEXT PRIMARY KEY,
    checkout_id  TEXT NOT NULL REFERENCES checkouts(id),
    method_id    TEXT NOT NULL REFERENCES merchant_payment_methods(id),
    provider     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated', 'succeeded', 'failed')),
    amount_minor INTEGER NOT NULL,
    currency     TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_payments_checkout ON payments (checkout_id);

-- Only inserted after full validation passes. The UNIQUE constraint is the
-- transaction-reuse guard: one real wallet transaction can pay one checkout.
CREATE TABLE transactions (
    id                    TEXT PRIMARY KEY,
    payment_id            TEXT NOT NULL REFERENCES payments(id),
    provider              TEXT NOT NULL,
    transaction_reference TEXT NOT NULL,
    amount_minor          INTEGER NOT NULL,
    currency              TEXT NOT NULL,
    recipient             TEXT NOT NULL,
    occurred_at           TEXT NOT NULL,
    raw_response          TEXT,
    created_at            TEXT NOT NULL,
    UNIQUE (provider, transaction_reference)
);

CREATE TABLE outbox_messages (
    id              TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    aggregate_id    TEXT NOT NULL,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_outbox_due ON outbox_messages (status, next_attempt_at);

CREATE TABLE webhook_deliveries (
    id          TEXT PRIMARY KEY,
    outbox_id   TEXT NOT NULL REFERENCES outbox_messages(id),
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id),
    attempt_no  INTEGER NOT NULL,
    status_code INTEGER,
    error       TEXT,
    duration_ms INTEGER,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_deliveries_outbox ON webhook_deliveries (outbox_id, attempt_no);

CREATE TABLE idempotency_keys (
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    key         TEXT NOT NULL,
    checkout_id TEXT NOT NULL REFERENCES checkouts(id),
    created_at  TEXT NOT NULL,
    PRIMARY KEY (merchant_id, key)
);
