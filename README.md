# PayBridge

Hosted checkout + payment verification + merchant webhooks for Ethiopian wallet payments
(Telebirr first). Merchants create a checkout, redirect the customer to our hosted page,
and the customer confirms payment by entering the **transaction reference** from their
wallet app. PayBridge asks the existing verification service for the authoritative
transaction facts, validates amount / currency / recipient / age / reuse, transitions the
checkout, and notifies the merchant via a signed webhook (outbox + exponential-backoff
retries).

## Documentation

- [docs/DESIGN.md](docs/DESIGN.md) — architecture, API surface, state machines,
  verification rules, webhook reliability, build plan
- [docs/VERIFICATION_SERVICE_CONTRACT.md](docs/VERIFICATION_SERVICE_CONTRACT.md) — the
  HTTP interface PayBridge expects from the existing verification service
- [docs/SCHEMA.sql](docs/SCHEMA.sql) — v1 database schema

## Quick start (mock verifier)

```bash
cp .env.example .env
cargo run                       # API + hosted checkout on :4000, SQLite DB auto-migrated
cargo run --example webhook_echo  # test webhook receiver on :4001 (separate terminal)
```

Dev merchant seeded automatically:

| Thing | Value |
| --- | --- |
| API key | `pb_sk_test_acme_local_only` |
| Merchant | Acme Tickets (dev) |
| Telebirr wallet | +251900000000 |
| Webhook endpoint | http://localhost:4001/webhooks (secret `whsec_seed_acme_0123456789abcdef0123456789abcdef`) |

### Try it

```bash
# 1. Merchant creates a checkout
curl -X POST http://localhost:4000/api/v1/checkouts \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer pb_sk_test_acme_local_only' \
  -H 'Idempotency-Key: demo-1' \
  -d '{"reference":"ORDER-12345","amount":500,"currency":"ETB",
       "items":[{"name":"Premium Ticket","quantity":1,"unitPrice":500}],
       "customer":{"name":"John Doe","email":"john@example.com"},
       "returnUrl":"https://merchant.example.com/result"}'

# 2. Open the returned paymentUrl in a browser, pick Telebirr, "pay", then
#    enter a transaction reference and hit Verify Payment.
```

With `VERIFIER=mock` (default), the reference you type controls the outcome:

| You enter | Result |
| --- | --- |
| `FT123456789` (anything unrecognized) | ✅ succeeds — amount/recipient match the checkout |
| `mismatch-FT1` | ❌ amount_mismatch (mock reports 100 ETB less) |
| `wrongwallet-FT1` | ❌ recipient_mismatch |
| `failed-FT1` | ❌ transaction_not_successful |
| `old-FT1` | ❌ transaction_too_old (48 h before checkout) |
| `missing-FT1` | ❌ transaction_not_found |

A successful verify fires `checkout.payment_succeeded` to the merchant's webhook
endpoint — watch it land in the echo receiver, signature and all. Retyping the same
reference on another checkout returns `transaction_already_used` (409).

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/api/v1/checkouts` | API key | Create checkout (`Idempotency-Key` supported) |
| GET | `/api/v1/checkouts/{id}` | API key | Checkout status incl. `transactionReference` once paid |
| POST | `/api/v1/checkouts/{id}/verify` | — (public, rate-limited) | JSON verify (browser calls this) |
| GET | `/c/{id}` | — | Hosted checkout page |
| POST | `/c/{id}/method` | — + CSRF | Select payment method |
| POST | `/c/{id}/verify` | — + CSRF | Form verify → PRG redirect / merchant returnUrl |
| GET | `/docs` | — | Scalar API reference (interactive, try-it-out) |
| GET | `/api-docs/openapi.json` | — | OpenAPI 3.1 document |
| GET | `/admin`… | admin password | Admin portal (dashboard, merchants, checkouts, webhooks, audit log) |
| GET | `/health` | — | Liveness |

## Admin portal, users & merchant signup

Sign in at [/admin/login](http://localhost:4000/admin/login) with an email +
password. The first superadmin is bootstrapped on startup from
`PAYBRIDGE_ADMIN_EMAIL` / `PAYBRIDGE_ADMIN_PASSWORD` (dev defaults
`admin@paybridge.local` / `paybridge-admin` — override both outside local
development). Passwords are stored as PBKDF2-SHA256 hashes; sessions are
HMAC cookies bound to the password hash, so changing or disabling a user kills
their sessions.

**Merchant signup** at [/signup](http://localhost:4000/signup): creates a
`pending` merchant plus its owner user (role `merchant`). Pending merchants
fail API-key authentication; a superadmin approves them from the merchant
detail page. Merchant-role users sign into a minimal portal at
[`/portal`](http://localhost:4000/portal) showing their approval status, their
own checkouts, and their API key prefixes — scoped strictly to their merchant.

**Roles** (enforced server-side; admin actions are audited with the acting
user): `superadmin` (full, incl. user management at `/admin/users` and merchant
approval), `operations` (retry webhooks), `developer` (retry webhooks, manage
API keys), `support` (view only), `merchant` (portal only). The admin portal
itself: dashboard (today's payments/volume/pending), merchant management
(suspend/reactivate, payment methods, API keys with rotate — secret shown
once), checkout search, webhook delivery inspection with retry, and an audit
log of every sensitive action.

## Verification rules (all must pass before a checkout is paid)

1. transaction exists at the provider (`transaction_not_found`)
2. transaction status is `success` (`transaction_not_successful`)
3. amount matches the checkout exactly (`amount_mismatch`)
4. currency matches (`currency_mismatch`)
5. recipient is the merchant's configured wallet (`recipient_mismatch`)
6. transaction happened after the checkout was created, ±2 min skew (`transaction_too_old`)
7. transaction was never consumed by another checkout (`transaction_already_used`,
   enforced by `UNIQUE (provider, transaction_reference)`)

Failed verifications leave the checkout `pending` — the customer can retry (max 10
attempts per checkout, 5 s cooldown). `succeeded` is terminal: further verifies get 409.

## Webhook payload

```json
{
  "eventId": "evt_01M…",
  "event": "checkout.payment_succeeded",
  "checkoutId": "chk_01M…",
  "reference": "ORDER-12345",
  "amount": "500.00",
  "amountMinor": 50000,
  "currency": "ETB",
  "paymentMethod": "telebirr",
  "transactionReference": "FT123456789",
  "status": "succeeded",
  "occurredAt": "2026-09-11T18:30:00Z"
}
```

Headers: `X-PayBridge-Signature: sha256=hex(HMAC_SHA256(secret, raw_body))`,
`X-PayBridge-Event-Id`, `X-PayBridge-Timestamp`. Merchants should verify the HMAC over
the raw body, enforce a ±5 min timestamp tolerance, and dedupe on `eventId`.
Retries: 30 s → 2 m → 10 m → 45 m → 2 h → 6 h → 24 h → dead-lettered.

## Switching to the real verification service

Set `VERIFIER=http`, `VERIFY_SERVICE_URL`, and (if required) `VERIFY_SERVICE_API_KEY`.
The expected contract is [docs/VERIFICATION_SERVICE_CONTRACT.md](docs/VERIFICATION_SERVICE_CONTRACT.md);
only `src/verify/http.rs` needs touching if it differs. **The `recipient` field must be
the exact receiving wallet (unmasked) — the recipient_mismatch rule depends on it.**

## Tests

```bash
cargo test
```

## Production notes

- SQLite is fine for dev; move to Postgres (schema notes in `docs/SCHEMA.sql`) and use
  `FOR UPDATE SKIP LOCKED` for multi-worker outbox claiming.
- Generate real API keys / webhook secrets (≥ 32 random bytes); the seeded ones are for
  local use only.
- Money is integer minor units everywhere; webhook amounts are decimal strings.
- Chrome-extension UX (auto-filling the reference) is deliberately out of scope — it
  only automates the last step of the hosted flow.
