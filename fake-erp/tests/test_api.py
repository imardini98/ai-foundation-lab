import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from fake_erp.main import API_PREFIX, authorize, create_app

SALES = {"X-User": "sales"}
WH = {"X-User": "warehouse"}


@pytest.fixture
def client():
    return TestClient(create_app())


def url(path: str) -> str:
    return API_PREFIX + path


# ---------------------------------------------------------------- reads

def test_get_item(client):
    r = client.get(url("/items/I-1000"), headers=SALES)
    assert r.status_code == 200
    assert r.json()["description"] == "Centrifugal pump KP-50"


def test_get_item_404(client):
    assert client.get(url("/items/NOPE"), headers=SALES).status_code == 404


def test_search_items(client):
    r = client.get(url("/items"), params={"q": "bearing"}, headers=WH)
    assert [i["item_no"] for i in r.json()] == ["I-3100"]


def test_bom_two_levels(client):
    r = client.get(url("/items/I-1000/bom"), headers=WH)
    assert r.status_code == 200
    motor = next(c for c in r.json()["components"] if c["item_no"] == "I-2000")
    assert motor["level"] == 1
    assert {c["item_no"] for c in motor["components"]} == {"I-3000", "I-3100"}
    assert all(c["level"] == 2 for c in motor["components"])


def test_bom_purchased_part_404(client):
    assert client.get(url("/items/I-3100/bom"), headers=WH).status_code == 404


def test_stock(client):
    r = client.get(url("/items/I-3100/stock"), headers=SALES)
    assert r.json()["available"] == 104


def test_sales_order_and_production_order(client):
    assert client.get(url("/sales-orders/SO-7001"), headers=SALES).json()["delivery_promise"] is None
    assert client.get(url("/production-orders/MO-5001"), headers=WH).json()["item_no"] == "I-1000"


# ---------------------------------------------------------------- authorization

@pytest.mark.parametrize("headers", [{}, {"X-User": ""}, {"X-User": "admin"}, {"X-User": "SALES"}])
def test_missing_or_unknown_role_is_403(client, headers):
    assert client.get(url("/items/I-1000"), headers=headers).status_code == 403


@pytest.mark.parametrize("path,headers", [
    ("/sales-orders/SO-7001", WH),
    ("/production-orders/MO-5001", SALES),
    ("/items/I-1000/bom", SALES),
])
def test_role_without_permission_is_403(client, path, headers):
    assert client.get(url(path), headers=headers).status_code == 403


def test_warehouse_cannot_set_delivery_promise(client):
    r = client.patch(url("/sales-orders/SO-7001/delivery-promise"),
                     json={"delivery_promise": "2026-12-01"}, headers={**WH, "Idempotency-Key": "k1"})
    assert r.status_code == 403
    assert client.get(url("/sales-orders/SO-7001"), headers=SALES).json()["delivery_promise"] is None


def test_403_before_404(client):
    # No information leak: unauthorized callers can't probe which IDs exist.
    assert client.get(url("/sales-orders/NOPE"), headers=WH).status_code == 403


def test_route_without_permission_is_denied_by_default():
    app = create_app()
    extra = APIRouter(prefix=API_PREFIX, dependencies=[Depends(authorize)])

    @extra.get("/secret")
    def secret():
        return {"ok": True}

    app.include_router(extra)
    c = TestClient(app)
    assert c.get(url("/secret"), headers=SALES).status_code == 403
    assert c.get(url("/secret"), headers=WH).status_code == 403


def test_every_api_route_declares_permission():
    app = create_app()
    for route in app.routes:
        if getattr(route, "path", "").startswith(API_PREFIX):
            assert (route.openapi_extra or {}).get("x-permission"), route.path


# ---------------------------------------------------------------- idempotency

PATCH = url("/sales-orders/SO-7001/delivery-promise")


def test_patch_requires_idempotency_key(client):
    r = client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers=SALES)
    assert r.status_code == 422


def test_patch_sets_delivery_promise(client):
    r = client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers={**SALES, "Idempotency-Key": "abc"})
    assert r.status_code == 200
    assert r.json()["delivery_promise"] == "2026-12-01"
    assert r.json()["status"] == "confirmed"
    assert "Idempotent-Replayed" not in r.headers


def test_same_key_same_request_replays_same_response(client):
    h = {**SALES, "Idempotency-Key": "abc"}
    first = client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers=h)
    # Someone else changes the order in between with another key...
    client.patch(PATCH, json={"delivery_promise": "2026-12-24"}, headers={**SALES, "Idempotency-Key": "other"})
    # ...the retry of the first call must return the original response, not re-apply it.
    replay = client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers=h)
    assert replay.status_code == first.status_code
    assert replay.json() == first.json()
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert client.get(url("/sales-orders/SO-7001"), headers=SALES).json()["delivery_promise"] == "2026-12-24"


def test_same_key_different_body_is_rejected(client):
    h = {**SALES, "Idempotency-Key": "abc"}
    client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers=h)
    r = client.patch(PATCH, json={"delivery_promise": "2027-01-15"}, headers=h)
    assert r.status_code == 422


def test_patch_rejects_unknown_fields(client):
    r = client.patch(PATCH, json={"delivery_promise": "2026-12-01", "status": "delivered"},
                     headers={**SALES, "Idempotency-Key": "x"})
    assert r.status_code == 422


# ---------------------------------------------------------------- contract

def test_openapi_contract(client):
    spec = client.get("/openapi.json").json()
    ops = {op["operationId"] for p in spec["paths"].values() for op in p.values()}
    assert ops == {"search_items", "get_item", "get_bom", "get_stock",
                   "get_sales_order", "set_delivery_promise", "get_production_order"}
    patch = spec["paths"][url("/sales-orders/{order_no}/delivery-promise")]["patch"]
    params = {p["name"]: p for p in patch["parameters"]}
    assert params["Idempotency-Key"]["required"] is True
    assert patch["x-permission"] == "sales_order:delivery_promise"
