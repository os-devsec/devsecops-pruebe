"""Capa de acceso a datos (SQLite).

VULNERABILIDAD 1: search_products_by_category() concatena SQL sin parametrizar.
"""
import sqlite3

from app.config import DATABASE_PATH


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _conn()
    conn.executescript(
        """
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS orders;

        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL
        );

        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            item TEXT NOT NULL,
            card_last4 TEXT NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO products (id, name, category, price) VALUES (?, ?, ?, ?)",
        [
            (1, "Laptop", "electronics", 1200.0),
            (2, "Keyboard", "electronics", 80.0),
            (3, "Coffee Mug", "kitchen", 15.0),
        ],
    )
    conn.executemany(
        "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
        [
            (1, "admin", "admin123", "admin"),
            (2, "alice", "alice123", "user"),
        ],
    )
    conn.executemany(
        "INSERT INTO orders (id, username, item, card_last4) VALUES (?, ?, ?, ?)",
        [
            (1, "alice", "Laptop", "1111"),
            (2, "admin", "Coffee Mug", "0004"),
        ],
    )
    conn.commit()
    conn.close()


def list_products() -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def search_products_by_category(category: str) -> list[dict]:
    """VULNERABILIDAD 1: SQL Injection.

    El parametro 'category' se concatena directamente en el query.
    Ejemplo de explotacion:  /products?category=' OR '1'='1
    """
    conn = _conn()
    query = f"SELECT * FROM products WHERE category = '{category}'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def list_users() -> list[dict]:
    conn = _conn()
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def find_user(username: str) -> dict | None:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_order(order_id: int) -> dict | None:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM orders WHERE id = ?", (order_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None
