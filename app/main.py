"""Shop API - demo de Secure Software Development y DevSecOps.

Contiene vulnerabilidades INTENCIONALES (detalladas en README.md).
"""
import logging
import traceback

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from app import db
from app.config import DEBUG, FAKE_API_KEY
from app.security import create_token, get_current_user

logger = logging.getLogger("shop")

app = FastAPI(title="Shop API", version="0.1.0", debug=DEBUG)
templates = Jinja2Templates(directory="templates")


@app.on_event("startup")
def startup() -> None:
    db.init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": app.version}


@app.get("/products")
def products(category: str = "") -> dict:
    """VULNERABILIDAD 1: 'category' pasa sin validar a la capa de datos."""
    if not category:
        return {"count": len(db.list_products()), "products": db.list_products()}
    results = db.search_products_by_category(category)
    return {"count": len(results), "products": results}


@app.get("/products.html")
def products_html(request: Request):
    return templates.TemplateResponse(
        "products.html",
        {"request": request, "products": db.list_products()},
    )


@app.post("/auth/login")
def login(username: str, password: str) -> dict:
    user = db.find_user(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": create_token(user["username"], user["role"])}


@app.get("/admin/users")
def admin_users(request: Request) -> dict:
    """VULNERABILIDAD 5: no comprueba rol; cualquiera es 'admin'."""
    user = get_current_user(request)
    return {
        "admin": user.get("sub") or user.get("username"),
        "users": db.list_users(),
    }


@app.get("/orders/{order_id}")
def get_order(order_id: int, request: Request) -> dict:
    """VULNERABILIDAD 6 (IDOR): no verifica la propiedad del pedido."""
    user = get_current_user(request)
    order = db.get_order(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return {
        "requested_by": user.get("sub") or user.get("username"),
        "order": {"id": order["id"], "item": order["item"]},
        "card_last4": order["card_last4"],
    }


@app.post("/checkout")
def checkout(payload: dict) -> dict:
    """VULNERABILIDAD 2: usa la API key hardcodeada (ficticia)."""
    return {
        "status": "ok",
        "provider": "stripe-demo",
        "charge_id": f"ch_{FAKE_API_KEY[-4:]}",
        "items": payload.get("items", []),
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """VULNERABILIDAD 4: devuelve el traceback y detalles tecnicos al cliente."""
    return JSONResponse(
        status_code=500,
        content={
            "error": f"Internal server error: {exc}",
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )
