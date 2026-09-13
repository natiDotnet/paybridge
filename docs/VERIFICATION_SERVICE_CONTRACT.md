# Verification Service — HTTP contract (real, as implemented)

PayBridge does not talk to wallets. It consumes the **existing verification
service**, which owns the providers (Telebirr, CBE Birr, Dashen, Awash, BoA,
Zemen) and validates transactions against expectations. Only
`src/verify/http.rs` speaks this contract (`VERIFIER=http`); everything else is
adapter-agnostic.

## Request

```text
POST {VERIFY_SERVICE_URL}/v1/transactions/verify
Content-Type: application/json

{
  "provider": "tele",
  "reference": "CHQ0FJ403O",
  "expected_amount_minor": 31200,
  "expected_currency": "ETB",
  "expected_recipient": "251911119144",
  "expected_created_at": "2026-09-13T13:03:05Z"
}
```

- `provider` — the service's slug for the provider. PayBridge maps its
  canonical ids: `telebirr` → `tele`, `cbebirr` → `cbe`; `awash` and any other
  ids pass through unchanged.
- `reference` — the customer-supplied transaction reference, passed verbatim
  (trimmed only). The service expands bare references to the provider URL
  itself and accepts full URLs as-is. Reference formats per provider:
  - `tele`: receipt id, e.g. `CHQ0FJ403O`
  - `cbe`: full id parameter (FT number + last 8 digits of the *payer*
    account), e.g. `FT25211G11JQ21827223` — the CBE URL cannot be built from
    the FT number alone
  - `dashen`: receipt path segment, e.g. `387ETAP2522000WK`
  - `awash`: receipt path segment, e.g. `-E41AE0D86FFA-21XYYW`
  - `boa`: `trx` value, e.g. `FT252113TRLT13487`
  - `zemen`: receipt path segment, e.g. `94497018108ATWR2520600HM`
- `expected_*` — what the service must match the transaction against: exact
  amount (minor units), currency, the receiving account, and the earliest
  allowed transaction time (the checkout's creation time).

## Response

- **200** — the service found a transaction satisfying the expectations.
  PayBridge parses the transaction facts tolerantly (snake_case or camelCase;
  `amount_minor` int or decimal `amount` string; `occurred_at` /
  `occurredAt` / `timestamp`), and re-validates amount, currency, recipient,
  age and status defensively in `domain::verify_checkout`. A 200 without an
  explicit `status` is treated as verified.
- **404** — no such transaction at the provider →
  `transaction_not_found` (customer may retry).
- **400 / 422** — the service rejected the expectations (no matching
  transaction) → `transaction_not_found` (checkout stays pending).
- **401 / 403 / 5xx / timeout (5 s)** — service problem → 502
  `verification_service_unavailable`; the attempt is logged but **not**
  counted against the customer's verify-attempt budget.

## Non-negotiables

1. The service must be the **source of truth** — PayBridge never caches a
   "success".
2. `expected_recipient` must be the exact receiving account (no masking);
   PayBridge sends the merchant's configured wallet and re-checks the
   `recipient` the service reports.
3. One reference = one immutable transaction record (idempotent lookups).

## Mock adapter (dev/test)

`VERIFIER=mock` implements the same boundary in-process:

| Reference prefix | Behavior |
| --- | --- |
| anything else | `success` with the **checkout's exact amount/currency** and recipient = the selected method's configured account (happy path) |
| `mismatch-…` | `success` but amount differs by 100 → exercises `amount_mismatch` |
| `wrongwallet-…` | `success` but recipient differs → `recipient_mismatch` |
| `failed-…` | `status:"failed"` → `transaction_not_successful` |
| `old-…` | transaction dated 48 h before the checkout → `transaction_too_old` |
| `missing-…` | 404 → `transaction_not_found` |
