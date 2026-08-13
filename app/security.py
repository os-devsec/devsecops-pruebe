"""Autenticacion con JWT.

VULNERABILIDAD 5: get_current_user() no valida el token ni el rol.
"""
import datetime

import jwt

from app.config import JWT_SECRET


def create_token(username: str, role: str) -> str:
    """Genera un JWT firmado con la clave hardcodeada de config.py."""
    payload = {
        "sub": username,
        "role": role,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def get_current_user(request) -> dict:
    """Devuelve el usuario 'autenticado'.

    VULNERABILIDAD 5: si la peticion no lleva un token valido se devuelve
    un usuario anonimo con rol 'admin'. Cualquiera accede a zonas
    administrativas sin credenciales.
    """
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        payload = verify_token(auth.split(" ", 1)[1])
        if payload:
            return payload
    return {"username": "anonymous", "role": "admin"}
