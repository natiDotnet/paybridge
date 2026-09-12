# Verification Service — HTTP contract (assumed v1)

PayBridge does not talk to wallets. It consumes the **existing verification service**,
which owns providers (Telebirr, CBE Birr, …) and returns authoritative transaction facts.
This document pins the minimal interface PayBridge needs. If the real service differs,
we adapt `src/verify/http.rs` only — nothing else in PayBridge changes.

## Request

```
GET {VERIFY_SERVICE_URL}/providers/{provider}/transactions/{reference}
Authorization: Bearer {VERIFY_SERVICE_API_KEY}      # if the service requires one
```

- `provider` — PayBridge's canonical provider id: `telebirr`, `cbebirr`, `mpesa`, `awash`.
- `reference` — the customer-supplied transaction reference, **URL-encode it verbatim**
  (trim whitespace only, never reformat or case-fold).

## Success response — 200

```json
{
  "status": "success",
  "transactionReference": "FT123456789",
  "provider": "telebirr",
  "amount": "500.00",
  "currency": "ETB",
  "recipient": "+251900000000",
  "occurredAt": "2026-09-11T18:25:44Z"
}
```

| Field | Type | Notes |
| --- | --- | --- |
| `status` | string | `success` \| `failed` \| `pending` — authoritative settlement state |
| `transactionReference` | string | Echo of the provider's reference (may differ in case from the input — PayBridge compares case-insensitively) |
| `amount` | string | Decimal with 2 dp. String, not float. |
| `currency` | string | ISO 4217, e.g. `ETB` |
| `recipient` | string | **The wallet/merchant account that actually received the money — must NOT be masked.** This is what PayBridge matches against the merchant's configured receiving account |
| `occurredAt` | string | ISO 8601 UTC timestamp of the original transaction (PayBridge rejects transactions older than the checkout) |
| `provider` | string | Echo of the provider — PayBridge asserts it matches the requested one |

## Failure responses

| HTTP | Meaning | PayBridge maps to |
| --- | --- | --- |
| 404 | No such transaction at the provider | `transaction_not_found` |
| 200 with `status:"pending"` | Exists, not settled | `transaction_not_successful` (checkout stays pending) |
| 200 with `status:"failed"` | Exists, failed/reversed | `transaction_not_successful` |
| 401/403 | Bad service credentials | 502 `verification_service_error` (config problem — never shown as customer failure) |
| 408/5xx/timeout (5 s budget) | Service unavailable | 502 `verification_service_unavailable` — attempt is logged, checkout stays pending, **no** verify-attempt penalty applied for these |

## Non-negotiables

1. The service must be the **source of truth** — PayBridge never caches a "success".
2. `recipient` must identify the receiving wallet exactly (no `09XX***44` masking),
   otherwise step 7 of the validation chain cannot prevent paying the wrong merchant.
3. One reference = one immutable transaction record (idempotent lookups).

## Mock adapter (dev/test)

`VERIFIER=mock` implements this contract in-process:

| Reference prefix | Behavior |
| --- | --- |
| anything else | `success` with the **checkout's exact amount/currency** and recipient = the selected method's configured account (happy path) |
| `mismatch-…` | `success` but amount differs by 100 → exercises `amount_mismatch` |
| `wrongwallet-…` | `success` but recipient differs → `recipient_mismatch` |
| `failed-…` | `status:"failed"` → `transaction_not_successful` |
| `missing-…` | 404 → `transaction_not_found` |
