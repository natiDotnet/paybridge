-- Dev seed: merchant "Acme Tickets".
-- API key (test only): pb_sk_test_acme_local_only
--   prefix: pb_sk_test_a
--   sha256: 2896fe5c9c68b9dc8a8854be5ba5fd9655fc640bb9096b9d89c9d7fc63c2898e
-- Webhook secret (test only): whsec_seed_acme_0123456789abcdef0123456789abcdef

INSERT INTO merchants (id, name, status, created_at)
VALUES ('mch_seed_acme', 'Acme Tickets (dev)', 'active', '2026-01-01T00:00:00Z');

INSERT INTO merchant_api_keys (id, merchant_id, prefix, key_hash, created_at)
VALUES ('key_seed_acme', 'mch_seed_acme', 'pb_sk_test_a',
        '2896fe5c9c68b9dc8a8854be5ba5fd9655fc640bb9096b9d89c9d7fc63c2898e',
        '2026-01-01T00:00:00Z');

INSERT INTO merchant_payment_methods
    (id, merchant_id, provider, display_name, account_identifier, instructions, status, created_at)
VALUES ('mpm_seed_telebirr', 'mch_seed_acme', 'telebirr', 'Telebirr', '+251900000000',
        'Open the Telebirr app and choose "Send Money"
Enter the number shown above
Send exactly the checkout amount
Copy the transaction reference from the confirmation
Return to this page and paste the reference',
        'active', '2026-01-01T00:00:00Z');

INSERT INTO webhook_endpoints (id, merchant_id, url, secret, status, created_at)
VALUES ('wh_seed_acme', 'mch_seed_acme', 'http://localhost:4001/webhooks',
        'whsec_seed_acme_0123456789abcdef0123456789abcdef', 'active', '2026-01-01T00:00:00Z');
