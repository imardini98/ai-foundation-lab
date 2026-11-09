# fake-erp

Fake ERP REST API (FastAPI) used as the backend that the MCP servers will wrap.

> The `/api/web/v1/...` route style imitates PASOE REST services. It has **not** been checked against the real Proalpha format.

## Run

```bash
uv sync
uv run uvicorn fake_erp.main:app --reload
```

- Contract: http://localhost:8000/openapi.json
- Docs: http://localhost:8000/docs
- Tests: `uv run pytest`

## Endpoints (`/api/web/v1`)

| Method | Path | operationId | Permission | Proalpha term |
|---|---|---|---|---|
| GET | `/items?q=` | `search_items` | `item:read` | Artikel |
| GET | `/items/{item_no}` | `get_item` | `item:read` | Artikel |
| GET | `/items/{item_no}/bom` | `get_bom` | `bom:read` | Stückliste |
| GET | `/items/{item_no}/stock` | `get_stock` | `stock:read` | Lagerbestand |
| GET | `/sales-orders/{order_no}` | `get_sales_order` | `sales_order:read` | Kundenauftrag |
| PATCH | `/sales-orders/{order_no}/delivery-promise` | `set_delivery_promise` | `sales_order:delivery_promise` | Lieferzusage |
| GET | `/production-orders/{order_no}` | `get_production_order` | `production_order:read` | Fertigungsauftrag |

## Security

Header `X-User: <user_id>`. The client sends **who** it is, never its role: the role is looked up server-side in the user directory (`users` in `data.json`; later the OAuth token's claims). Everything not explicitly allowed returns 403: no user, unknown user, missing permission, or a route that declares no `x-permission`. The auth check runs before the lookup, so an unauthorized caller can't learn which IDs exist.

| User | Role |
|---|---|
| `alice` | sales |
| `carol` | sales |
| `bob` | warehouse |

| Permission | sales | warehouse |
|---|:-:|:-:|
| item:read | ✓ | ✓ |
| stock:read | ✓ | ✓ |
| sales_order:read | ✓ | |
| sales_order:delivery_promise | ✓ | |
| bom:read | | ✓ |
| production_order:read | | ✓ |

### Audit

Every successful write appends an entry with timestamp, `user_id`, role, action, resource, before/after values and the idempotency key. Entries go to `app.state.audit_log` and to the `fake_erp.audit` logger. Rejected writes and idempotent replays are not logged.

## PATCH delivery promise

**Business rules**
- The date must be today or later → otherwise 422.
- The date must not be before `order_date` → otherwise 422.
- A `delivered` order can't be changed → 409.
- On success, `status` becomes `confirmed`.

**Idempotency**
- `Idempotency-Key` is required (422 if it's missing).
- Keys are scoped per **user and operation**, so two users can use the same key without colliding.
- Same user + same key + same request → the stored response comes back with `Idempotent-Replayed: true`, and nothing is changed again.
- Same user + same key + different request → 422.
- Keys expire after 24 h; the store is capped at 10,000 entries (oldest are evicted first).

## Known gaps (TODO)

- **No stock reservation.** Confirming a delivery promise doesn't touch `reserved` or check availability, so two orders can be promised against the same stock.
- **Idempotency store and audit log live in memory.** In production they belong in the database: an idempotency table with a unique index on (user, operation, key) and a TTL job, plus an append-only audit table.
- **`X-User` is trusted as-is.** It's a stand-in for OAuth (planned for S2), where the user id and role come from a verified token.

## Data

`fake_erp/data.json` is loaded into memory at startup: 3 users, 5 items, a 2-level BOM (I-1000 → I-2000 → I-3000/I-3100), 4 sales orders (one already delivered), 2 production orders.
