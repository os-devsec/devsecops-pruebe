# Shop API - Demo DevSecOps

Aplicación web pequeña (API REST en Python/FastAPI) creada **deliberadamente insegura** para
demostrar el ciclo:

```
INSECURE CODE -> DETECTION -> PIPELINE FAIL -> REMEDIATION -> RESCAN -> PASS -> DEPLOY
```

Se integra Snyk (SAST + SCA + Secret scanning) en GitHub Actions. Todo es reproducible en
local y en GitHub sin infraestructura cloud.

> ADVERTENCIA: todos los datos y credenciales del código son **FICTICIOS** (la API key
> `sk_live_...` no es real). No desplegar fuera del entorno de demostración.

---

## 1. Arquitectura

```
 Developer (local)           GitHub                       GitHub Actions
 +-------------+     push/PR  +--------------+    +------------------------------+
 | VS Code     | ----------> | Repo + PR    |--> | ci.yml                       |
 | venv+uvicorn| <---------- | annotations  |    | test -> snyk-oss -> snyk-code|
 +-------------+    feedback  +--------------+    |            -> security-gate  |
                                                  |            -> docker-build   |
                                                  +---------------+--------------+
                                                                  | (solo main, gate OK)
                                                           +------v------+
                                                           | GHCR image  |--> smoke test
                                                           | shop-api    |    (curl /health)
                                                           +-------------+
```

- **App local-first**: SQLite embebida, sin servicios externos.
- **Snyk como CLI dentro de los jobs** (`snyk test`, `snyk code test`, `snyk monitor`)
  autenticada con el secret `SNYK_TOKEN`.
- **Security Gate**: script Python que agrega el JSON de Snyk y decide FAIL/PASS según la
  política de `security-policy.json`, y comenta el resultado en el PR.

## 2. Stack

| Capa | Tecnología |
|---|---|
| API | Python 3.11 + FastAPI + Uvicorn |
| Datos | SQLite (stdlib `sqlite3`) |
| Templates | Jinja2 (dependencia vulnerable a propósito) |
| Auth | PyJWT (Bearer token con claim `role`) |
| Tests | pytest + `TestClient` (httpx) |
| CI/CD | GitHub Actions (workflows `CI` y `Deploy`) |
| SAST/SCA/Secrets | Snyk (CLI + GitHub Action) |
| Packaging | Docker + GHCR (GitHub Container Registry) |

## 3. Vulnerabilidades intencionales

| # | Vulnerabilidad | Dónde | Cómo explotarla | Cómo la detecta Snyk | Cómo corregirla |
|---|---|---|---|---|---|
| 1 | **SQL Injection** | `app/db.py::search_products_by_category` | `GET /products?category=' OR '1'='1` | Snyk Code (SAST): flujo de dato desde el parámetro HTTP hasta `conn.execute` | Query parametrizada con `?` |
| 2 | **Secreto hardcodeado** | `app/config.py::FAKE_API_KEY` (y `JWT_SECRET`) | Revisar código / commits | Snyk Code (regla de secretos) + GitHub secret scanning | Mover a variable de entorno / GitHub Secret |
| 3 | **Dependencias vulnerables** | `requirements.txt` | - | Snyk Open Source (SCA): CVEs de jinja2, starlette, uvicorn | Actualizar a versiones corregidas |
| 4 | **Errores verbosos** | `app/main.py` handler de excepciones + `DEBUG=True` | `GET /products?category='` (comilla simple) devuelve traceback completo | Snyk Code (revelación de detalles internos) | Respuesta genérica + log en servidor, `DEBUG=False` |
| 5 | **Autorización rota** | `app/security.py::get_current_user` + `/admin/users` | `GET /admin/users` sin token → entras como `admin` | Snyk Code (control de acceso débil) | Validar token y exigir rol `admin` |
| 6 | **IDOR** *(opcional)* | `app/main.py::get_order` | `GET /orders/2` con token de `alice` lee el pedido de `admin` | **NO la detecta** (es lógica de negocio) → lección de revisión humana | Verificar que `order.username == user["sub"]` |

## 4. Flujo del pipeline

```
Developer -> push/PR -> ci.yml
  1. test (pytest)              feedback rápido, siempre corre
  2. snyk-oss (SCA)             escanea TODAS las severidades, NO bloquea (solo avisa)
  3. snyk-code (SAST)           escanea TODAS las severidades, NO bloquea (solo avisa)
  4. security-gate              agrega JSONs, aplica policy, FAIL/PASS + PR comment
  5. docker-build               verifica que la imagen compila (independiente del gate)
  -------------------------------------------------------------------------------
  6. Deploy (solo main)         se dispara SOLO si el workflow CI terminó con éxito
                               (workflow_run conclusion == success) -> GHCR + smoke test
```

- Los jobs **snyk-oss** y **snyk-code** reportan **todos** los hallazgos (critical/high/
  medium/low) como anotaciones de warning. **No bloquean**: si hay vulnerabilidades solo
  avisan con `::warning::` y terminan OK; fallan únicamente ante un error de la
  herramienta (p.ej. token inválido o escaneo roto).
- La **decisión de bloqueo es exclusiva del Security Gate**, que aplica la política de
  `security-policy.json` sobre los JSON completos. Así todo hallazgo queda visible en el
  PR, pero solo lo crítico/alto (y los secretos) detienen el merge.

El job `Deploy` usa `workflow_run` para que **nunca se despliegue código que no haya
superado el Security Gate**.

## 5. Security Gate (criterio)

Política en `security-policy.json`:

```json
{
  "sca":     { "fail_on": ["critical", "high"], "warn_on": ["medium", "low"] },
  "sast":    { "fail_on": ["critical", "high"], "warn_on": ["medium", "low"] },
  "secrets": { "fail_on": "any" }
}
```

- **Critical/High (CVSS >= 7.0)** bloquean: explotables remotamente, alto impacto.
- **Secretos: fallan SIEMPRE**, independientemente de la severidad (una credencial expuesta
  es riesgo inmediato y exige rotación).
- **Medium/Low**: no bloquean velocidad; se anotan como avisos en el reporte del PR
  (deuda técnica controlada).
- El script `scripts/security_gate.py` parsea el JSON de Snyk, clasifica hallazgos,
  escribe `security-gate-report.md` y devuelve `exit 1` si algo bloquea.

## 6. Ejecución en local

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Probar los exploits (en otra terminal)

```bash
# 1) SQL Injection - devuelve TODOS los productos (incluye 'kitchen')
curl "http://localhost:8000/products?category=' OR '1'='1"

# 2) Secreto hardcodeado - mira app/config.py
# 3) Dependencias vulnerables - ejecuta: snyk test
# 4) Error verboso - devuelve el traceback completo
curl "http://localhost:8000/products?category='"

# 5) Autorización rota - SIN token accedes como admin
curl http://localhost:8000/admin/users

# 6) IDOR - con token de alice lees el pedido de admin (id=2)
TOKEN=$(curl -s -X POST "http://localhost:8000/auth/login?username=alice&password=alice123" | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/orders/2
```

Los tests (`pytest tests -v`) **pasan** con el código inseguro: la funcionalidad funciona,
pero la seguridad falla. Ese es el punto de la demo.

## 7. Snyk en local (antes del pipeline)

```bash
# Login una vez (plan gratuito): https://app.snyk.io -> Settings -> API token
snyk auth

snyk test                   # SCA: dependencias vulnerables
snyk code test              # SAST: vulnerabilidades en el código + secretos
snyk monitor                # registra el proyecto en tu dashboard de Snyk
snyk code test --json > snyk-code.json   # útil para el Security Gate
```

## 8. Configurar GitHub

1. Crea un repo en GitHub y sube este proyecto (ver "Pasos de la demo").
2. Habilitar Actions (por defecto) y **GitHub secret scanning**:
   `Settings -> Code security and analysis -> Secret scanning`.
3. Crea el secret `SNYK_TOKEN`:
   `Settings -> Secrets and variables -> Actions -> New repository secret`.
   (Token de https://app.snyk.io -> Account settings -> General -> Auth Token).
4. El workflow `Deploy` usa `GITHUB_TOKEN` con permiso `packages: write` para publicar la
   imagen en GHCR (ya configurado en el workflow).

## 9. Pasos de la demo (narrativa)

| Paso | Acción | Resultado |
|---|---|---|
| 1 | Commit inicial con la app **insegura** | - |
| 2 | Abre un PR contra `main` | CI corre: tests PASS, **snyk-oss y snyk-code muestran hallazgos (warning)**, **gate FAIL** |
| 3 | Revisa el comentario del gate en el PR | Lista de hallazgos con ubicación y fix |
| 4 | Remedia **una vulnerabilidad por commit** (sección 10) | Rescan en el mismo PR |
| 5 | Cuando el gate dé **PASS**, mergea | El `Deploy` corre sobre `main` |
| 6 | Verifica el deploy | Imagen en GHCR + smoke test `curl /health` OK |
| 7 | *(Opcional)* Snyk Monitor | Dashboard con el historial del proyecto |

## 10. Remediación (ejemplos de corrección)

### 10.1 SQL Injection -> `app/db.py`

```python
# ANTES
query = f"SELECT * FROM products WHERE category = '{category}'"
rows = conn.execute(query).fetchall()

# DESPUES (query parametrizada)
rows = conn.execute(
    "SELECT * FROM products WHERE category = ?", (category,)
).fetchall()
```

### 10.2 Secreto hardcodeado -> `app/config.py`

```python
# ANTES
FAKE_API_KEY = "DEMO_STRIPE_API_KEY_NOT_A_REAL_SECRET"
JWT_SECRET = "sup3r-s3cret-demo-jwt-secret-please-rotate"
DEBUG = True

# DESPUES (valores desde el entorno; se inyectan en CI como secrets)
FAKE_API_KEY = os.environ.get("PAYMENT_API_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
```

### 10.3 Dependencias vulnerables -> `requirements.txt`

```python
# ANTES
fastapi==0.110.0
uvicorn==0.23.2
jinja2==3.0.3

# DESPUES (versiones corregidas)
fastapi==0.115.12
uvicorn==0.34.0
jinja2==3.1.5
```

Snyk Open Source indica las versiones que corrigen cada CVE.

### 10.4 Errores verbosos -> `app/main.py`

```python
import logging
logger = logging.getLogger("shop")

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s", request.url)   # detalle SOLO en logs
    return JSONResponse(status_code=500, content={"error": "Internal server error"})
```

### 10.5 Autorización -> `app/security.py` + `app/main.py`

```python
def get_current_user(request):
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = verify_token(auth.split(" ", 1)[1])
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

@app.get("/admin/users")
def admin_users(request: Request) -> dict:
    user = get_current_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return {"admin": user["sub"], "users": db.list_users()}
```

### 10.6 IDOR -> `app/main.py::get_order`

```python
if order["username"] != user["sub"]:
    raise HTTPException(status_code=403, detail="Not your order")
```

## 11. Extras para la charla

- `.snyk`: plantilla de gobernanza (ignorar con motivo + caducidad). En la demo **no** se
  ignoran hallazgos para que el pipeline falle.
- `snyk monitor` registra el proyecto y permite ver el **historial** en el dashboard.
- GitHub **secret scanning** es una segunda línea de defensa fuera del pipeline.
- `requirements.locked.txt`: versión remediada de referencia (comentada).

## 12. Desarrollo con IA y seguridad

El código generado por IA acelera la producción, pero también introduce fallos de seguridad
típicos, y los introduce **más rápido** que un humano. Problemas habituales:

- **Validación insuficiente** de entradas (se confía en lo que llega del usuario).
- **Errores demasiado verbosos** que filtran internals, rutas o stacktraces.
- **Secretos hardcodeados** (API keys, tokens) en el propio código.
- **Controles de autorización incorrectos o ausentes** (checks de rol mal colocados, IDOR).
- Dependencias dudosas o **dependency confusion** (paquetes que "parecen" oficiales).
- Configuraciones inseguras por defecto (`debug=True`, TLS deshabilitado, permisos laxos).

| Qué detecta Snyk (automatizable) | Qué requiere revisión humana |
|---|---|
| SAST: SQLi, XSS, path traversal, crypto débil, errores verbosos, secretos | Lógica de negocio y autorización a nivel de dominio (IDOR, broken access control) |
| SCA: dependencias vulnerables en `requirements.txt` y transitivas | Threat modeling y decisiones de diseño |
| Secret scanning: credenciales expuestas en código y commits | Rotación y gestión de secretos en producción |
| Monitoreo continuo del proyecto (Snyk Monitor) | Prompt injection y diseño de prompts |
| | Clasificación de datos y cumplimiento (PCI, GDPR, etc.) |

**Conclusión práctica**: la IA genera más código por hora; el escaneo automatizado (Snyk)
es el guardrail que permite mantener el ritmo sin sacrificar la barrera de seguridad. Pero
las decisiones de negocio y de diseño (autorización, datos sensibles, amenazas) **no pueden
delegarse** a un modelo: requieren revisión humana.

## 13. Troubleshooting

- `snyk` no autentica en CI: comprueba que el secret se llame `SNYK_TOKEN` y exista en el repo.
- GHCR rechaza el push: el nombre del repo no debe contener mayúsculas (el workflow ya lo
  pasa a minúsculas); revisa `packages: write` en permisos.
- `cryptography==3.4.8` no instalaba en Python 3.11+: por eso la demo usa `jinja2==3.0.3`
  (puro Python, con CVE-2024-56326 High) en vez de una librería C vieja sin wheels.
- Snyk Code no detecta el IDOR: es intencional; usa el paso 6 para explicar el límite
  del SAST.
