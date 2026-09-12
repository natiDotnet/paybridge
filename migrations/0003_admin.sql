-- Admin portal: audit trail of every sensitive admin operation
-- (merchant suspend/reactivate, webhook retries, admin logins).

CREATE TABLE audit_logs (
    id          TEXT PRIMARY KEY,             -- aud_01K…
    actor       TEXT NOT NULL,                -- 'admin' until admin users/roles exist
    action      TEXT NOT NULL,                -- e.g. 'merchant.suspended', 'webhook.retried'
    resource    TEXT NOT NULL,                -- e.g. 'merchant', 'webhook_event'
    resource_id TEXT NOT NULL,
    ip          TEXT,                         -- x-forwarded-for / x-real-ip when present
    metadata    TEXT,                         -- JSON details, e.g. {"delivery":"whd_01K…"}
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_logs (created_at DESC);
