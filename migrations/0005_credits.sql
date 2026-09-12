-- Prepaid verification credits: merchants buy credit (1 ETB = 1 credit) to
-- activate and to pay for the verification API. Each successful verification
-- consumes 1 credit; at zero, verification stops until they top up.

ALTER TABLE merchants ADD COLUMN credit_balance INTEGER NOT NULL DEFAULT 0;

-- One row per credit purchase; the linked checkout is a normal hosted
-- checkout paid to the platform merchant, and settling it (same transaction
-- as the checkout success) credits the buyer.
CREATE TABLE credit_purchases (
    id           TEXT PRIMARY KEY,      -- crp_01K…
    merchant_id  TEXT NOT NULL REFERENCES merchants(id),
    checkout_id  TEXT NOT NULL UNIQUE REFERENCES checkouts(id),
    credits      INTEGER NOT NULL CHECK (credits > 0),
    amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
    created_at   TEXT NOT NULL
);

-- Audit ledger of every balance movement (+purchase / -verification / +grant).
CREATE TABLE credit_ledger (
    id          TEXT PRIMARY KEY,       -- crl_01K…
    merchant_id TEXT NOT NULL REFERENCES merchants(id),
    delta       INTEGER NOT NULL,
    reason      TEXT NOT NULL CHECK (reason IN ('purchase', 'verification', 'admin_grant')),
    checkout_id TEXT,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_ledger_merchant ON credit_ledger (merchant_id, created_at);

-- The platform merchant that sells credits (its own receiving wallet).
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

-- Dev convenience: the seeded demo merchant gets starting credit.
UPDATE merchants SET credit_balance = 1000 WHERE id = 'mch_seed_acme';
