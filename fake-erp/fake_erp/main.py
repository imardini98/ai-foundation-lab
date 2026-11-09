"""Fake ERP REST API, loosely modelled on Proalpha / PASOE web services.

Security model (deny by default):
  * Every route under /api must declare `x-permission` in its openapi_extra.
    A route without it is rejected with 403 for everybody.
  * The caller sends `X-User: <role>`. Missing or unknown role -> 403.
    The role must hold the route's permission, otherwise -> 403.
"""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Path as PathParam, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

DATA_FILE = Path(__file__).with_name("data.json")
API_PREFIX = "/api/web/v1"


# --------------------------------------------------------------------------- roles

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


def perm(name: str) -> dict:
    """openapi_extra marker: the permission a route requires (also visible in the OpenAPI contract)."""
    return {"x-permission": name}


def authorize(
    request: Request,
    x_user: Annotated[
        str | None,
        Header(description="Caller role: `sales` or `warehouse`."),
    ] = None,
) -> Role:
    route = request.scope.get("route")
    required = (getattr(route, "openapi_extra", None) or {}).get("x-permission")
    if not required:
        # Deny by default: a route that forgot to declare a permission is closed.
        raise HTTPException(403, "Route declares no permission")
    try:
        role = Role(x_user) if x_user else None
    except ValueError:
        role = None
    if role is None:
        raise HTTPException(403, "Missing or unknown role in X-User")
    if required not in ROLE_PERMISSIONS[role]:
        raise HTTPException(403, f"Role '{role.value}' lacks permission '{required}'")
    return role


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
    status: Literal["open", "confirmed", "delivered"]
    lines: list[SalesOrderLine]


class DeliveryPromiseUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    delivery_promise: date = Field(description="Promised delivery date (ISO date)", examples=["2026-12-01"])


class ProductionOrder(BaseModel):
    order_no: str = Field(examples=["MO-5001"])
    item_no: str
    quantity: float
    status: Literal["planned", "released", "started", "completed"]
    start_date: date
    end_date: date
    sales_order_no: str | None


ERR_403 = {403: {"model": Error, "description": "Missing or insufficient role"}}
ERR_404 = {404: {"model": Error, "description": "Not found"}}

ItemNo = Annotated[str, PathParam(description="Item number, e.g. I-1000")]
SalesOrderNo = Annotated[str, PathParam(description="Sales order number, e.g. SO-7001")]


# --------------------------------------------------------------------------- app

def create_app(data_file: Path = DATA_FILE) -> FastAPI:
    db = copy.deepcopy(json.loads(data_file.read_text(encoding="utf-8")))
    idempotency_store: dict[str, dict] = {}
    lock = threading.Lock()

    app = FastAPI(
        title="Fake ERP",
        version="0.1.0",
        description=(
            "Fake ERP REST API (Proalpha/PASOE-like) used as a backend for MCP experiments. "
            "Authentication via the `X-User` header (role). Anything not explicitly allowed is rejected with 403."
        ),
    )
    api = APIRouter(prefix=API_PREFIX, dependencies=[Depends(authorize)], responses=ERR_403)

    def get_or_404(table: str, key: str, label: str) -> dict:
        row = db[table].get(key)
        if row is None:
            raise HTTPException(404, f"{label} '{key}' not found")
        return row

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
        responses={**ERR_404, 422: {"description": "Invalid input, or Idempotency-Key reused with a different request"}},
        summary="Set the delivery promise of a sales order (idempotent)",
        description=(
            "Sets the promised delivery date and moves the status to `confirmed`. "
            "`Idempotency-Key` is required. The same key with the same request returns the stored response "
            "(header `Idempotent-Replayed: true`) without applying the change again; "
            "the same key with a different request returns 422."
        ),
    )
    def set_delivery_promise(
        order_no: SalesOrderNo,
        body: DeliveryPromiseUpdate,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1, max_length=255,
                                               description="Unique key per business change, e.g. a UUID")],
    ):
        fingerprint = hashlib.sha256(
            json.dumps({"order_no": order_no, "body": body.model_dump(mode="json")}, sort_keys=True).encode()
        ).hexdigest()
        with lock:
            stored = idempotency_store.get(idempotency_key)
            if stored is not None:
                if stored["fingerprint"] != fingerprint:
                    raise HTTPException(422, "Idempotency-Key was already used for a different request")
                return JSONResponse(stored["body"], status_code=stored["status"],
                                    headers={"Idempotent-Replayed": "true"})

            order = get_or_404("sales_orders", order_no, "Sales order")
            order["delivery_promise"] = body.delivery_promise.isoformat()
            order["status"] = "confirmed"
            result = SalesOrder.model_validate(order).model_dump(mode="json")
            idempotency_store[idempotency_key] = {"fingerprint": fingerprint, "status": 200, "body": result}
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
