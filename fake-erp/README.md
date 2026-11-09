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

Header `X-User: <role>`. Everything not explicitly allowed returns 403 (no role, unknown role, missing permission, or a route that declares no `x-permission`). The auth check runs before the lookup, so an unauthorized caller can't learn which IDs exist.

| Permission | sales | warehouse |
|---|:-:|:-:|
| item:read | ✓ | ✓ |
| stock:read | ✓ | ✓ |
| sales_order:read | ✓ | |
| sales_order:delivery_promise | ✓ | |
| bom:read | | ✓ |
| production_order:read | | ✓ |

## Idempotency (PATCH delivery promise)

- `Idempotency-Key` is required (422 if it's missing).
- Same key + same request → the stored response comes back with `Idempotent-Replayed: true`, and nothing is changed again.
- Same key + different request → 422.
- The store lives in memory and is lost on restart, just like the data.

## Data

`fake_erp/data.json` is loaded into memory at startup: 5 items, a 2-level BOM (I-1000 → I-2000 → I-3000/I-3100), 3 sales orders, 2 production orders.
