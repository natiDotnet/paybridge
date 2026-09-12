-- Admin users & roles + merchant self-signup onboarding.
-- Platform roles follow the permission matrix in DESIGN docs:
--   superadmin  full access, incl. user management
--   operations  view merchants, retry webhooks
--   support     view only
--   developer   view merchants/payments, retry webhooks, manage API keys
-- 'merchant' users own a single merchant (merchant_id NOT NULL) and use
-- the /portal surface; they sign up at /signup and start pending approval.

CREATE TABLE users (
    id            TEXT PRIMARY KEY,         -- usr_01K…
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,            -- pbkdf2_sha256$iterations$salt$hash
    role          TEXT NOT NULL CHECK (role IN
                  ('superadmin', 'operations', 'support', 'developer', 'merchant')),
    merchant_id   TEXT REFERENCES merchants(id),
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_users_merchant ON users (merchant_id);

-- Merchant self-signup onboarding: signups land 'pending' and are approved by
-- a superadmin. Existing (seeded/admin-created) merchants are 'approved'.
ALTER TABLE merchants ADD COLUMN onboarding_status TEXT NOT NULL DEFAULT 'approved';
