-- PostgreSQL schema: combined equivalent of SQLite migrations 0001-0007.
-- BIGINT mirrors SQLite INTEGER so i64 columns decode on both drivers.
-- PayBridge schema for PostgreSQL (fresh databases).
-- This is the combined equivalent of migrations 0001-0007 (the SQLite
-- migrations can't run on PG as-is: 0007 uses SQLite's table-rebuild recipe).
-- Timestamps stay ISO-8601 TEXT because the application currently writes
-- ISO strings; switch to timestamptz when the runtime itself moves to PG.

-- 1. core
CREATE TABLE merchants (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    onboarding_status TEXT NOT NULL DEFAULT 'approved',
    credit_balance    BIGINT NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL
);

CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN
                  ('superadmin', 'operations', 'support', 'developer', 'merchant')),
    merchant_id   TEXT REFERENCES merchants(id),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_users_merchant ON users (merchant_id);

CREATE TABLE provider_instructions (
    provider     TEXT PRIMARY KEY,
    instructions TEXT NOT NULL
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
    provider           TEXT NOT NULL CHECK (provider IN
                       ('telebirr', 'cbebirr', 'cbe', 'boa', 'zemen', 'dashen', 'awash', 'mpesa')),
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

-- 2. checkouts
CREATE TABLE checkouts (
    id                 TEXT PRIMARY KEY,
    merchant_id        TEXT NOT NULL REFERENCES merchants(id),
    reference          TEXT NOT NULL,
    amount_minor       BIGINT NOT NULL CHECK (amount_minor > 0),
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
CREATE INDEX idx_checkouts_expiry ON checkouts (status, expires_at);

CREATE TABLE checkout_items (
    id               TEXT PRIMARY KEY,
    checkout_id      TEXT NOT NULL REFERENCES checkouts(id),
    name             TEXT NOT NULL,
    quantity         BIGINT NOT NULL CHECK (quantity > 0),
    unit_price_minor BIGINT NOT NULL CHECK (unit_price_minor >= 0)
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

CREATE TABLE idempotency_keys (
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    key         TEXT NOT NULL,
    checkout_id TEXT NOT NULL REFERENCES checkouts(id),
    created_at  TEXT NOT NULL,
    PRIMARY KEY (merchant_id, key)
);

CREATE TABLE payments (
    id           TEXT PRIMARY KEY,
    checkout_id  TEXT NOT NULL REFERENCES checkouts(id),
    method_id    TEXT NOT NULL REFERENCES merchant_payment_methods(id),
    provider     TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'initiated' CHECK (status IN ('initiated', 'succeeded', 'failed')),
    amount_minor BIGINT NOT NULL,
    currency     TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_payments_checkout ON payments (checkout_id);

CREATE TABLE transactions (
    id                    TEXT PRIMARY KEY,
    payment_id            TEXT NOT NULL REFERENCES payments(id),
    provider              TEXT NOT NULL,
    transaction_reference TEXT NOT NULL,
    amount_minor          BIGINT NOT NULL,
    currency              TEXT NOT NULL,
    recipient             TEXT NOT NULL,
    occurred_at           TEXT NOT NULL,
    raw_response          TEXT,
    created_at            TEXT NOT NULL,
    UNIQUE (provider, transaction_reference)
);

-- 3. credits
CREATE TABLE credit_purchases (
    id           TEXT PRIMARY KEY,
    merchant_id  TEXT NOT NULL REFERENCES merchants(id),
    checkout_id  TEXT NOT NULL UNIQUE REFERENCES checkouts(id),
    credits      BIGINT NOT NULL CHECK (credits > 0),
    amount_minor BIGINT NOT NULL CHECK (amount_minor > 0),
    created_at   TEXT NOT NULL
);

CREATE TABLE credit_ledger (
    id          TEXT PRIMARY KEY,
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    delta       BIGINT NOT NULL,
    reason      TEXT NOT NULL CHECK (reason IN ('purchase', 'verification', 'admin_grant')),
    checkout_id TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_ledger_merchant ON credit_ledger (merchant_id, created_at);

-- 4. outbox + deliveries
CREATE TABLE outbox_messages (
    id              TEXT PRIMARY KEY,
    event_type      TEXT NOT NULL,
    aggregate_id    TEXT NOT NULL,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'dead')),
    attempts        BIGINT NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_error      TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_outbox_due ON outbox_messages (status, next_attempt_at);

CREATE TABLE webhook_deliveries (
    id          TEXT PRIMARY KEY,
    outbox_id   TEXT NOT NULL REFERENCES outbox_messages(id),
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id),
    attempt_no  BIGINT NOT NULL,
    status_code INTEGER,
    error       TEXT,
    duration_ms INTEGER,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_deliveries_outbox ON webhook_deliveries (outbox_id, attempt_no);

-- 5. audit
CREATE TABLE audit_logs (
    id          TEXT PRIMARY KEY,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    ip          TEXT,
    metadata    TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_logs (created_at DESC);

-- 6. required seed: central customer steps per provider
INSERT INTO provider_instructions (provider, instructions) VALUES
('telebirr',
 'Open the Telebirr app and choose "Send Money"
Enter the receiving number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('cbebirr',
 'Open the CBE Birr app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('cbe',
 'Open the CBE Birr app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation (FT number + account digits)
Return to this page and paste the full reference'),
('boa',
 'Open the Bank of Abyssinia mobile app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('zemen',
 'Open the Zemen Bank mobile app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the receipt number from the confirmation
Return to this page and paste the reference'),
('dashen',
 'Open the Dashen mobile app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the receipt number from the confirmation
Return to this page and paste the reference'),
('awash',
 'Open the Awash mobile app and choose "Transfer"
Enter the receiving account shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference'),
('mpesa',
 'Open the M-Pesa app and choose "Send Money"
Enter the receiving number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference');

-- 7. required seed: the platform merchant that sells verification credit
INSERT INTO merchants (id, name, status, onboarding_status, created_at)
VALUES ('mch_seed_paybridge', 'PayBridge Credits', 'active', 'approved', '2026-01-01T00:00:00Z');

INSERT INTO merchant_payment_methods
    (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at)
VALUES ('mpm_seed_pb_telebirr', 'mch_seed_paybridge', 'telebirr', 'Telebirr', '+251900000001',
        'Open the Telebirr app and choose "Send Money"
Enter the number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference',
        'active', '2026-01-01T00:00:00Z');
