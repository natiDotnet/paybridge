-- New wallet/bank payment methods: CBE, Bank of Abyssinia, Zemen, Dashen.
-- The provider CHECK constraint can't be altered in SQLite, so the table and
-- its dependents are rebuilt. sqlx always runs migrations inside a
-- transaction, so FK enforcement can't be disabled: we drop leaf tables
-- first (so no implicit delete violates a FK), recreate everything with the
-- new CHECK, and copy the data back through backup tables.
-- Legacy ids ('telebirr', 'cbebirr') remain valid for existing rows.

-- 1. back up the affected subtree (plain tables: no constraints, no FKs)
CREATE TABLE _m7_bak_mpm AS SELECT * FROM merchant_payment_methods;
CREATE TABLE _m7_bak_checkouts AS SELECT * FROM checkouts;
CREATE TABLE _m7_bak_checkout_items AS SELECT * FROM checkout_items;
CREATE TABLE _m7_bak_payment_attempts AS SELECT * FROM payment_attempts;
CREATE TABLE _m7_bak_idempotency_keys AS SELECT * FROM idempotency_keys;
CREATE TABLE _m7_bak_credit_purchases AS SELECT * FROM credit_purchases;
CREATE TABLE _m7_bak_payments AS SELECT * FROM payments;
CREATE TABLE _m7_bak_transactions AS SELECT * FROM transactions;

-- 2. drop leaf-first (transactions and webhook tables are untouched)
DROP TABLE transactions;
DROP TABLE credit_purchases;
DROP TABLE payment_attempts;
DROP TABLE idempotency_keys;
DROP TABLE checkout_items;
DROP TABLE payments;
DROP TABLE checkouts;
DROP TABLE merchant_payment_methods;

-- 3. recreate, with the extended provider set on merchant_payment_methods
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

CREATE TABLE checkout_items (
    id               TEXT PRIMARY KEY,
    checkout_id      TEXT NOT NULL REFERENCES checkouts(id),
    name             TEXT NOT NULL,
    quantity         INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_minor INTEGER NOT NULL CHECK (unit_price_minor >= 0)
);

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
    amount_minor INTEGER NOT NULL,
    currency     TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE credit_purchases (
    id           TEXT PRIMARY KEY,
    merchant_id  TEXT NOT NULL REFERENCES merchants(id),
    checkout_id  TEXT NOT NULL UNIQUE REFERENCES checkouts(id),
    credits      INTEGER NOT NULL CHECK (credits > 0),
    amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
    created_at   TEXT NOT NULL
);

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

-- 4. indexes dropped with their tables
CREATE INDEX idx_checkouts_merchant ON checkouts (merchant_id, created_at);
CREATE INDEX idx_checkouts_expiry ON checkouts (status, expires_at);
CREATE INDEX idx_checkout_items_checkout ON checkout_items (checkout_id);
CREATE INDEX idx_attempts_checkout ON payment_attempts (checkout_id, created_at);
CREATE INDEX idx_payments_checkout ON payments (checkout_id);
CREATE INDEX idx_payment_methods_merchant ON merchant_payment_methods (merchant_id, status);

-- 5. restore, parent-first
INSERT INTO merchant_payment_methods SELECT * FROM _m7_bak_mpm;
INSERT INTO checkouts SELECT * FROM _m7_bak_checkouts;
INSERT INTO checkout_items SELECT * FROM _m7_bak_checkout_items;
INSERT INTO payment_attempts SELECT * FROM _m7_bak_payment_attempts;
INSERT INTO idempotency_keys SELECT * FROM _m7_bak_idempotency_keys;
INSERT INTO credit_purchases SELECT * FROM _m7_bak_credit_purchases;
INSERT INTO payments SELECT * FROM _m7_bak_payments;
INSERT INTO transactions SELECT * FROM _m7_bak_transactions;

DROP TABLE _m7_bak_transactions;
DROP TABLE _m7_bak_checkouts;
DROP TABLE _m7_bak_checkout_items;
DROP TABLE _m7_bak_payment_attempts;
DROP TABLE _m7_bak_idempotency_keys;
DROP TABLE _m7_bak_credit_purchases;
DROP TABLE _m7_bak_payments;
DROP TABLE _m7_bak_mpm;

-- 6. customer steps for the new providers (central config)
INSERT INTO provider_instructions (provider, instructions) VALUES
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
Return to this page and paste the reference');
