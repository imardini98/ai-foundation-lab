"""Fake ERP REST API, loosely modelled on Proalpha / PASOE web services.

Security model (deny by default):
  * Every route under /api must declare `x-permission` in its openapi_extra.
    A route without it is rejected with 403 for everybody.
  * The caller sends `X-User: <user_id>`. The role is NOT taken from the client:
    it is looked up server-side in the user directory (today data.json, later the
    OAuth token's claims). Missing or unknown user -> 403.
  * The user's role must hold the route's permission, otherwise -> 403.
  * Every write appends an audit entry (who, role, what, before/after).
  * Every 403 appends a security entry (separate from the business audit).
  * Business dates ("today") are evaluated in the company time zone.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Callable, Literal
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Path as PathParam, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

DATA_FILE = Path(__file__).with_name("data.json")
API_PREFIX = "/api/web/v1"
COMPANY_TZ = ZoneInfo("Europe/Berlin")

# Idempotency store limits. In-memory is fine for the lab.
# TODO(prod): persist in the database (unique index on user_id+operation+key) with a TTL job.
IDEMPOTENCY_TTL = timedelta(hours=24)
IDEMPOTENCY_MAX_ENTRIES = 10_000

audit_logger = logging.getLogger("fake_erp.audit")
security_logger = logging.getLogger("fake_erp.security")


# --------------------------------------------------------------------------- sales order states

SalesOrderStatus = Literal["open", "confirmed", "delivered", "cancelled"]

# Allowed status transitions. Anything not listed is rejected with 409.
# confirmed -> confirmed is a reschedule of an existing delivery promise.
SALES_ORDER_TRANSITIONS: dict[str, frozenset[str]] = {
    "open": frozenset({"confirmed", "cancelled"}),
    "confirmed": frozenset({"confirmed", "delivered", "cancelled"}),
    "delivered": frozenset(),
    "cancelled": frozenset(),
}


# --------------------------------------------------------------------------- identity & roles

class Role(str, Enum):
    sales = "sales"
    warehouse = "warehouse"


ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.sales: frozenset({
        "item:read",
        "sales_order:read",
        "sales_order:delivery_promise",
        "stock:read",
    }),
    Role.warehouse: frozenset({
        "item:read",
        "bom:read",
        "production_order:read",
        "stock:read",
    }),
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: Role


def perm(name: str) -> dict:
    """openapi_extra marker: the permission a route requires (also visible in the OpenAPI contract)."""
    return {"x-permission": name}


def authorize(
    request: Request,
    x_user: Annotated[
        str | None,
        Header(description="Caller's user id (e.g. `alice`). The role is resolved server-side."),
    ] = None,
) -> Principal:
    route = request.scope.get("route")
    required = (getattr(route, "openapi_extra", None) or {}).get("x-permission")
    user = request.app.state.users.get(x_user) if x_user else None

    def deny(reason: str, role: str | None = None):
        entry = {
            "at": request.app.state.now().isoformat(),
            "event": "access_denied",
            "user_id": (x_user or "")[:64] or None,  # raw header value, truncated: it is untrusted
            "known_user": user is not None,
            "role": role,
            "method": request.method,
            "path": request.url.path,
            "operation_id": getattr(route, "operation_id", None),
            "required_permission": required,
            "reason": reason,
        }
        request.app.state.security_log.append(entry)
        security_logger.warning(json.dumps(entry))
        raise HTTPException(403, reason)

    if not required:
        # Deny by default: a route that forgot to declare a permission is closed.
        deny("Route declares no permission")
    if user is None:
        deny("Missing or unknown user in X-User")
    try:
        role = Role(user["role"])
    except ValueError:
        deny("User has no valid role")
    if required not in ROLE_PERMISSIONS[role]:
        deny(f"Role '{role.value}' lacks permission '{required}'", role=role.value)
    return Principal(user_id=user["user_id"], role=role)


CurrentPrincipal = Annotated[Principal, Depends(authorize)]


# --------------------------------------------------------------------------- models

class Error(BaseModel):
    detail: str


class Item(BaseModel):
    item_no: str = Field(examples=["I-1000"])
    description: str
    item_type: Literal["finished_good", "subassembly", "purchased_part"]
    unit: str
    price_eur: float


class BomComponent(BaseModel):
    level: int = Field(description="1 = direct component, 2 = component of a subassembly")
    item_no: str
    description: str
    quantity: float = Field(description="Quantity per unit of the parent item")
    components: list[BomComponent] = []


class Bom(BaseModel):
    item_no: str
    description: str
    components: list[BomComponent]


class Stock(BaseModel):
    item_no: str
    location: str
    on_hand: float
    reserved: float
    available: float = Field(description="on_hand - reserved")


class SalesOrderLine(BaseModel):
    line: int
    item_no: str
    quantity: float


class SalesOrder(BaseModel):
    order_no: str = Field(examples=["SO-7001"])
    customer_no: str
    customer_name: str
    order_date: date
    requested_date: date
    delivery_promise: date | None
    status: SalesOrderStatus
    lines: list[SalesOrderLine]


class DeliveryPromiseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    delivery_promise: date = Field(
        description="Promised delivery date (ISO date). Must be today or later and not before the order date.",
        examples=["2026-12-01"],
    )


class ProductionOrder(BaseModel):
    order_no: str = Field(examples=["MO-5001"])
    item_no: str
    quantity: float
    status: Literal["planned", "released", "started", "completed"]
    start_date: date
    end_date: date
    sales_order_no: str | None


ERR_403 = {403: {"model": Error, "description": "Missing user or insufficient permission"}}
ERR_404 = {404: {"model": Error, "description": "Not found"}}

ItemNo = Annotated[str, PathParam(description="Item number, e.g. I-1000")]
SalesOrderNo = Annotated[str, PathParam(description="Sales order number, e.g. SO-7001")]


# --------------------------------------------------------------------------- app

def create_app(
    data_file: Path = DATA_FILE,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> FastAPI:
    db = copy.deepcopy(json.loads(data_file.read_text(encoding="utf-8")))
    # key: (user_id, operation_id, idempotency_key) -> {fingerprint, status, body, created_at}
    idempotency_store: OrderedDict[tuple[str, str, str], dict] = OrderedDict()
    lock = threading.Lock()

    app = FastAPI(
        title="Fake ERP",
        version="0.2.0",
        description=(
            "Fake ERP REST API (Proalpha/PASOE-like) used as a backend for MCP experiments. "
            "Authentication via the `X-User` header (user id; role resolved server-side). "
            "Anything not explicitly allowed is rejected with 403."
        ),
    )
    app.state.users = db["users"]
    app.state.now = now
    app.state.audit_log = []  # TODO(prod): append-only table, not process memory.
    app.state.security_log = []  # TODO(prod): ship to the SIEM / observability stack.
    api = APIRouter(prefix=API_PREFIX, dependencies=[Depends(authorize)], responses=ERR_403)

    def get_or_404(table: str, key: str, label: str) -> dict:
        row = db[table].get(key)
        if row is None:
            raise HTTPException(404, f"{label} '{key}' not found")
        return row

    def audit(principal: Principal, action: str, resource: str, before: dict, after: dict, idempotency_key: str):
        entry = {
            "at": now().isoformat(),
            "user_id": principal.user_id,
            "role": principal.role.value,
            "action": action,
            "resource": resource,
            "before": before,
            "after": after,
            "idempotency_key": idempotency_key,
        }
        app.state.audit_log.append(entry)
        audit_logger.info(json.dumps(entry))

    def purge_expired_idempotency(current: datetime):
        while idempotency_store:
            _, oldest = next(iter(idempotency_store.items()))
            if current - oldest["created_at"] < IDEMPOTENCY_TTL and len(idempotency_store) < IDEMPOTENCY_MAX_ENTRIES:
                break
            idempotency_store.popitem(last=False)

    # ---- Items
    @api.get("/items", response_model=list[Item], operation_id="search_items",
             tags=["Items"], openapi_extra=perm("item:read"),
             summary="Full-text search for items (number or description)")
    def search_items(q: Annotated[str, Query(min_length=1, description="Search text, case-insensitive")]):
        needle = q.casefold()
        return [i for i in db["items"].values()
                if needle in i["item_no"].casefold() or needle in i["description"].casefold()]

    @api.get("/items/{item_no}", response_model=Item, operation_id="get_item",
             tags=["Items"], openapi_extra=perm("item:read"), responses=ERR_404,
             summary="Get one item")
    def get_item(item_no: ItemNo):
        return get_or_404("items", item_no, "Item")

    # ---- Bill of materials
    def explode(item_no: str, level: int) -> list[dict]:
        return [
            {
                "level": level,
                "item_no": pos["item_no"],
                "description": db["items"][pos["item_no"]]["description"],
                "quantity": pos["quantity"],
                "components": explode(pos["item_no"], level + 1),
            }
            for pos in db["boms"].get(item_no, [])
        ]

    @api.get("/items/{item_no}/bom", response_model=Bom, operation_id="get_bom",
             tags=["Bill of materials"], openapi_extra=perm("bom:read"), responses=ERR_404,
             summary="Multi-level bill of materials for an item")
    def get_bom(item_no: ItemNo):
        item = get_or_404("items", item_no, "Item")
        if item_no not in db["boms"]:
            raise HTTPException(404, f"Item '{item_no}' has no bill of materials")
        return {"item_no": item_no, "description": item["description"], "components": explode(item_no, 1)}

    # ---- Stock
    @api.get("/items/{item_no}/stock", response_model=Stock, operation_id="get_stock",
             tags=["Stock"], openapi_extra=perm("stock:read"), responses=ERR_404,
             summary="Stock level for an item")
    def get_stock(item_no: ItemNo):
        get_or_404("items", item_no, "Item")
        s = get_or_404("stock", item_no, "Stock for item")
        return {**s, "available": s["on_hand"] - s["reserved"]}

    # ---- Sales orders
    @api.get("/sales-orders/{order_no}", response_model=SalesOrder, operation_id="get_sales_order",
             tags=["Sales orders"], openapi_extra=perm("sales_order:read"), responses=ERR_404,
             summary="Get one sales order")
    def get_sales_order(order_no: SalesOrderNo):
        return get_or_404("sales_orders", order_no, "Sales order")

    @api.patch(
        "/sales-orders/{order_no}/delivery-promise", response_model=SalesOrder,
        operation_id="set_delivery_promise", tags=["Sales orders"],
        openapi_extra=perm("sales_order:delivery_promise"),
        responses={
            **ERR_404,
            409: {"model": Error, "description": "Order status does not allow this change (delivered or cancelled)"},
            422: {"description": "Invalid input, date in the past or before the order date, "
                                 "or Idempotency-Key reused with a different request"},
        },
        summary="Set the delivery promise of a sales order (idempotent)",
        description=(
            "Sets the promised delivery date and moves the status to `confirmed`.\n\n"
            "Rules: the date must be today or later (company time zone Europe/Berlin) and not before "
            "`order_date`. The status transition must be allowed: `open` and `confirmed` (reschedule) can be "
            "confirmed; `delivered` and `cancelled` cannot (409).\n\n"
            "`Idempotency-Key` is required and scoped per user and operation. The same user sending the same key "
            "with the same request gets the stored response (header `Idempotent-Replayed: true`) without the change "
            "being applied again; the same key with a different request returns 422. Keys expire after 24 h.\n\n"
            "Does not reserve stock yet."
        ),
    )
    def set_delivery_promise(
        order_no: SalesOrderNo,
        body: DeliveryPromiseUpdate,
        principal: CurrentPrincipal,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=255,
                                               description="Unique key per business change, e.g. a UUID")],
    ):
        operation = "set_delivery_promise"
        store_key = (principal.user_id, operation, idempotency_key)
        fingerprint = hashlib.sha256(
            json.dumps({"order_no": order_no, "body": body.model_dump(mode="json")}, sort_keys=True).encode()
        ).hexdigest()
        current = now()
        with lock:
            purge_expired_idempotency(current)
            stored = idempotency_store.get(store_key)
            if stored is not None:
                if stored["fingerprint"] != fingerprint:
                    raise HTTPException(422, "Idempotency-Key was already used for a different request")
                return JSONResponse(stored["body"], status_code=stored["status"],
                                    headers={"Idempotent-Replayed": "true"})

            order = get_or_404("sales_orders", order_no, "Sales order")
            if "confirmed" not in SALES_ORDER_TRANSITIONS[order["status"]]:
                raise HTTPException(
                    409, f"Sales order '{order_no}' is {order['status']} and cannot be confirmed")
            if body.delivery_promise < current.astimezone(COMPANY_TZ).date():
                raise HTTPException(422, "delivery_promise must not be in the past")
            if body.delivery_promise < date.fromisoformat(order["order_date"]):
                raise HTTPException(422, "delivery_promise must not be before the order date")

            # TODO: confirming a date should reserve stock (or check ATP) for each order line.
            # Without it, two orders can be promised against the same available quantity.

            before = {"delivery_promise": order["delivery_promise"], "status": order["status"]}
            order["delivery_promise"] = body.delivery_promise.isoformat()
            order["status"] = "confirmed"
            after = {"delivery_promise": order["delivery_promise"], "status": order["status"]}
            audit(principal, operation, f"sales_order:{order_no}", before, after, idempotency_key)

            result = SalesOrder.model_validate(order).model_dump(mode="json")
            idempotency_store[store_key] = {"fingerprint": fingerprint, "status": 200, "body": result,
                                            "created_at": current}
            return JSONResponse(result, status_code=200)

    # ---- Production orders
    @api.get("/production-orders/{order_no}", response_model=ProductionOrder, operation_id="get_production_order",
             tags=["Production orders"], openapi_extra=perm("production_order:read"), responses=ERR_404,
             summary="Get one production order")
    def get_production_order(order_no: Annotated[str, PathParam(description="Production order number, e.g. MO-5001")]):
        return get_or_404("production_orders", order_no, "Production order")

    app.include_router(api)
    return app


app = create_app()
