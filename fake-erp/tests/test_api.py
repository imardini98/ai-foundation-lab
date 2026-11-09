from datetime import datetime, timedelta, timezone

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from fake_erp.main import API_PREFIX, authorize, create_app

SALES = {"X-User": "alice"}
SALES_2 = {"X-User": "carol"}
WH = {"X-User": "bob"}


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def app(clock):
    return create_app(now=clock)


@pytest.fixture
def client(app):
    return TestClient(app)


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

@pytest.mark.parametrize("headers", [
    {}, {"X-User": ""}, {"X-User": "mallory"}, {"X-User": "ALICE"},
    # A role name is not a user: clients can't claim a role directly.
    {"X-User": "sales"}, {"X-User": "warehouse"},
])
def test_missing_or_unknown_user_is_403(client, headers):
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


def test_route_without_permission_is_denied_by_default(app):
    extra = APIRouter(prefix=API_PREFIX, dependencies=[Depends(authorize)])

    @extra.get("/secret")
    def secret():
        return {"ok": True}

    app.include_router(extra)
    c = TestClient(app)
    assert c.get(url("/secret"), headers=SALES).status_code == 403
    assert c.get(url("/secret"), headers=WH).status_code == 403


def test_every_api_route_declares_permission(app):
    for route in app.routes:
        if getattr(route, "path", "").startswith(API_PREFIX):
            assert (route.openapi_extra or {}).get("x-permission"), route.path


# ---------------------------------------------------------------- delivery promise: business rules

PATCH = url("/sales-orders/SO-7001/delivery-promise")


def patch(client, headers, date_str, key, order="SO-7001"):
    return client.patch(url(f"/sales-orders/{order}/delivery-promise"),
                        json={"delivery_promise": date_str}, headers={**headers, "Idempotency-Key": key})


def test_patch_sets_delivery_promise(client):
    r = patch(client, SALES, "2026-12-01", "abc")
    assert r.status_code == 200
    assert r.json()["delivery_promise"] == "2026-12-01"
    assert r.json()["status"] == "confirmed"
    assert "Idempotent-Replayed" not in r.headers


def test_today_is_allowed(client):
    assert patch(client, SALES, "2026-11-09", "k").status_code == 200


def test_past_date_is_rejected(client):
    r = patch(client, SALES, "2026-11-08", "k")
    assert r.status_code == 422
    assert "past" in r.json()["detail"]


def test_date_before_order_date_is_rejected(app, client, clock):
    clock.t = datetime(2026, 10, 1, tzinfo=timezone.utc)  # SO-7001 was ordered 2026-10-20
    r = patch(client, SALES, "2026-10-10", "k")
    assert r.status_code == 422
    assert "order date" in r.json()["detail"]


def test_delivered_order_cannot_be_changed(client):
    r = patch(client, SALES, "2026-12-01", "k", order="SO-7004")
    assert r.status_code == 409
    assert client.get(url("/sales-orders/SO-7004"), headers=SALES).json()["status"] == "delivered"


def test_cancelled_order_cannot_be_confirmed(client):
    r = patch(client, SALES, "2026-12-01", "k", order="SO-7005")
    assert r.status_code == 409
    assert "cancelled" in r.json()["detail"]


def test_confirmed_order_can_be_rescheduled(client):
    assert patch(client, SALES, "2026-12-01", "k1").status_code == 200
    r = patch(client, SALES, "2026-12-15", "k2")
    assert r.status_code == 200
    assert r.json()["delivery_promise"] == "2026-12-15"


def test_transition_table_covers_every_status():
    from typing import get_args

    from fake_erp.main import SALES_ORDER_TRANSITIONS, SalesOrderStatus

    statuses = set(get_args(SalesOrderStatus))
    assert set(SALES_ORDER_TRANSITIONS) == statuses
    assert all(targets <= statuses for targets in SALES_ORDER_TRANSITIONS.values())


def test_today_uses_company_time_zone(client, clock):
    # 2026-11-08 23:30 UTC is already 2026-11-09 00:30 in Hamburg (CET, UTC+1).
    clock.t = datetime(2026, 11, 8, 23, 30, tzinfo=timezone.utc)
    r = patch(client, SALES, "2026-11-08", "k")
    assert r.status_code == 422
    assert "past" in r.json()["detail"]
    assert patch(client, SALES, "2026-11-09", "k2").status_code == 200


def test_patch_rejects_unknown_fields(client):
    r = client.patch(PATCH, json={"delivery_promise": "2026-12-01", "status": "delivered"},
                     headers={**SALES, "Idempotency-Key": "x"})
    assert r.status_code == 422


def test_patch_unknown_order_404(client):
    assert patch(client, SALES, "2026-12-01", "k", order="SO-9999").status_code == 404


# ---------------------------------------------------------------- idempotency

def test_patch_requires_idempotency_key(client):
    r = client.patch(PATCH, json={"delivery_promise": "2026-12-01"}, headers=SALES)
    assert r.status_code == 422


def test_same_key_same_request_replays_same_response(client):
    first = patch(client, SALES, "2026-12-01", "abc")
    # Someone else changes the order in between with another key...
    patch(client, SALES, "2026-12-24", "other")
    # ...the retry of the first call must return the original response, not re-apply it.
    replay = patch(client, SALES, "2026-12-01", "abc")
    assert replay.status_code == first.status_code
    assert replay.json() == first.json()
    assert replay.headers["Idempotent-Replayed"] == "true"
    assert client.get(url("/sales-orders/SO-7001"), headers=SALES).json()["delivery_promise"] == "2026-12-24"


def test_same_key_different_body_is_rejected(client):
    patch(client, SALES, "2026-12-01", "abc")
    assert patch(client, SALES, "2027-01-15", "abc").status_code == 422


def test_idempotency_key_is_scoped_per_user(client):
    first = patch(client, SALES, "2026-12-01", "shared-key")
    # Another user reusing the same key is NOT served alice's response and is not rejected.
    other = patch(client, SALES_2, "2026-12-20", "shared-key")
    assert other.status_code == 200
    assert "Idempotent-Replayed" not in other.headers
    assert other.json()["delivery_promise"] == "2026-12-20"
    assert first.json()["delivery_promise"] == "2026-12-01"


def test_idempotency_key_expires_after_ttl(client, clock):
    patch(client, SALES, "2026-12-01", "abc")
    clock.t += timedelta(hours=25)
    r = patch(client, SALES, "2027-01-15", "abc")
    assert r.status_code == 200
    assert "Idempotent-Replayed" not in r.headers


def test_replay_does_not_add_audit_entry(app, client):
    patch(client, SALES, "2026-12-01", "abc")
    patch(client, SALES, "2026-12-01", "abc")
    assert len(app.state.audit_log) == 1


# ---------------------------------------------------------------- audit

def test_write_is_audited_with_user_and_before_after(app, client):
    patch(client, SALES, "2026-12-01", "abc")
    (entry,) = app.state.audit_log
    assert entry["user_id"] == "alice"
    assert entry["role"] == "sales"
    assert entry["action"] == "set_delivery_promise"
    assert entry["resource"] == "sales_order:SO-7001"
    assert entry["before"] == {"delivery_promise": None, "status": "open"}
    assert entry["after"] == {"delivery_promise": "2026-12-01", "status": "confirmed"}
    assert entry["idempotency_key"] == "abc"


def test_rejected_writes_are_not_audited(app, client):
    patch(client, SALES, "2026-11-01", "k1")          # past date
    patch(client, SALES, "2026-12-01", "k2", "SO-7004")  # delivered
    patch(client, WH, "2026-12-01", "k3")              # forbidden
    assert app.state.audit_log == []


# ---------------------------------------------------------------- security log

def test_forbidden_write_goes_to_security_log_not_audit(app, client):
    patch(client, WH, "2026-12-01", "k")
    assert app.state.audit_log == []
    (entry,) = app.state.security_log
    assert entry["event"] == "access_denied"
    assert entry["user_id"] == "bob"
    assert entry["known_user"] is True
    assert entry["role"] == "warehouse"
    assert entry["method"] == "PATCH"
    assert entry["operation_id"] == "set_delivery_promise"
    assert entry["required_permission"] == "sales_order:delivery_promise"


def test_unknown_user_is_logged_and_header_truncated(app, client):
    client.get(url("/items/I-1000"), headers={"X-User": "x" * 500})
    client.get(url("/items/I-1000"))
    first, second = app.state.security_log
    assert first["known_user"] is False and len(first["user_id"]) == 64
    assert second["user_id"] is None


def test_allowed_requests_are_not_security_logged(app, client):
    client.get(url("/items/I-1000"), headers=SALES)
    assert app.state.security_log == []


# ---------------------------------------------------------------- contract

def test_openapi_contract(client):
    spec = client.get("/openapi.json").json()
    ops = {op["operationId"] for p in spec["paths"].values() for op in p.values()}
    assert ops == {"search_items", "get_item", "get_bom", "get_stock",
                   "get_sales_order", "set_delivery_promise", "get_production_order"}
    patch_op = spec["paths"][url("/sales-orders/{order_no}/delivery-promise")]["patch"]
    params = {p["name"]: p for p in patch_op["parameters"]}
    assert params["Idempotency-Key"]["required"] is True
    assert set(patch_op["responses"]) >= {"200", "403", "404", "409", "422"}
    assert patch_op["x-permission"] == "sales_order:delivery_promise"
