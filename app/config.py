"""Configuracion de la aplicacion.

ADVERTENCIA: contiene vulnerabilidades INTENCIONALES para la demo.
Todos los valores son FICTICIOS, ninguno es una credencial real.
"""

import os

# VULNERABILIDAD 2: secreto (API key) hardcodeado en el codigo.
# Formato de ejemplo estilo Stripe, PERO es un valor inventado.
FAKE_API_KEY = "DEMO_STRIPE_API_KEY_NOT_A_REAL_SECRET"

# VULNERABILIDAD (extra): clave de firma JWT hardcodeada.
JWT_SECRET = "sup3r-s3cret-demo-jwt-secret-please-rotate"

# VULNERABILIDAD 4: modo debug activado (expone errores y stacktraces).
DEBUG = True

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "demo.db")
