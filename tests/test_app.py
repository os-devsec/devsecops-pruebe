import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_products_all(client):
    r = client.get("/products")
    assert r.status_code == 200
    assert r.json()["count"] == 3


def test_products_by_category(client):
    r = client.get("/products", params={"category": "electronics"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2
    assert all(p["category"] == "electronics" for p in body["products"])


def test_products_html(client):
    r = client.get("/products.html")
    assert r.status_code == 200
    assert "Product Catalog" in r.text


def test_login_ok(client):
    r = client.post(
        "/auth/login",
        params={"username": "alice", "password": "alice123"},
    )
    assert r.status_code == 200
    assert "token" in r.json()


def test_login_bad_password(client):
    r = client.post(
        "/auth/login",
        params={"username": "alice", "password": "wrong"},
    )
    assert r.status_code == 401


def test_admin_users_with_valid_token(client):
    token = client.post(
        "/auth/login",
        params={"username": "admin", "password": "admin123"},
    ).json()["token"]
    r = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["admin"] == "admin"


def test_get_own_order(client):
    token = client.post(
        "/auth/login",
        params={"username": "alice", "password": "alice123"},
    ).json()["token"]
    r = client.get("/orders/1", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["order"]["item"] == "Laptop"


def test_checkout(client):
    r = client.post("/checkout", json={"items": ["Laptop"]})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
