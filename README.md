# Meridian Ledger — Target de Pruebas para Pentesting

Aplicación web (SaaS de operaciones financieras) **deliberadamente vulnerable**, diseñada como
*target* aislado para validar la capacidad de descubrimiento de un escáner/pentester
automatizado. La interfaz y el código imitan una aplicación de producción real, pero contiene
**19 vulnerabilidades avanzadas** (lógica, arquitectura, capa de API, sesiones, auth y RCE),
elegidas por ser difíciles de detectar con escáneres convencionales.

> El detalle de cada vector de ataque, su explotación manual y por qué es difícil de
> detectar está en **[`ATTACK_GUIDE.md`](./ATTACK_GUIDE.md)**.

---

## ⚠️ Advertencia de uso (léela)

Esta aplicación es **insengura por diseño** e incluye RCE real y SSRF sin filtrar. Trátala como
material peligroso:

- **Solo en entornos aislados y efímeros.** Despliega, escanea y **destruye** la instancia.
- **No introduzcas datos reales** ni credenciales reales. Todo es de laboratorio.
- **No la dejes expuesta públicamente más tiempo del necesario.** Cualquiera que la encuentre
  obtiene RCE sobre el contenedor. Si la publicas en Railway, restringe el acceso (URL privada,
  dominio no indexado, o un proxy con auth por delante) y bórrala al terminar.
- No la uses contra infraestructura que no sea tuya. El SSRF apunta a metadatos de nube a
  propósito: úsalo únicamente contra tu propio entorno de prueba.

`LAB_MODE=1` (por defecto) muestra un banner de aviso en la UI. No desactiva ninguna
vulnerabilidad; es solo un recordatorio visual.

---

## Arquitectura

| Capa        | Tecnología                                             |
|-------------|--------------------------------------------------------|
| Backend     | Node.js + Express 4                                    |
| Frontend    | HTML/JS puro servido por el backend + Tailwind vía CDN |
| Base datos  | SQLite (archivo local, `better-sqlite3`), reseed en cada arranque |
| Sesiones    | Cookie `sid` opaca + store en memoria                  |

```
meridian-vuln-lab/
├── server.js                 # entrypoint; escucha en process.env.PORT
├── package.json              # scripts (start) + deps
├── Procfile / railway.json   # config de despliegue
├── src/
│   ├── db.js                 # init + seed de SQLite
│   ├── session.js            # store de sesión + requireAuth
│   ├── audit.js              # middleware de auditoría (SQLi en X-Forwarded-For)
│   ├── lib/
│   │   ├── deepmerge.js      # merge recursivo inseguro (prototype pollution)
│   │   ├── unserialize.js    # deserializador inseguro (RCE)
│   │   └── fetchUrl.js       # fetch server-side sin filtrar (SSRF)
│   └── routes/               # un archivo por dominio funcional
└── public/                   # index.html + app.js (panel Tailwind)
```

Elegí **Node.js** porque dos de las vulnerabilidades pedidas (Prototype Pollution y la
deserialización estilo `node-serialize`) son específicas de este runtime.

El servidor escucha en `0.0.0.0` y en `process.env.PORT` (o `3000` en local), tal como Railway
lo requiere.

---

## Cuentas de laboratorio (seed)

| Email                | Password         | Rol    | Notas                                  |
|----------------------|------------------|--------|----------------------------------------|
| `alice@meridian.io`  | `Password123!`   | member | Cuenta "atacante" para las demos       |
| `bob@meridian.io`    | `Sunshine#2024`  | member | Víctima (invoice confidencial, saldo)  |
| `admin@meridian.io`  | `M3ridian!Admin` | admin  | Datos privilegiados a escalar          |

La base de datos se **recrea y re-siembra en cada arranque**, de modo que cada escaneo parte de
un estado limpio y determinista.

---

## Ejecutar en local

Requiere Node.js 18+ (build nativo de `better-sqlite3`; necesita toolchain de compilación).

```bash
npm install
npm start
# -> http://localhost:3000
```

Health check: `GET /healthz`.

---

## Despliegue en Railway

La app ya está lista para Railway (detección Nixpacks, `start` script, puerto dinámico).

### Opción A — Desde GitHub (recomendada)

1. Sube esta carpeta a un repositorio (por ejemplo privado).
2. En [railway.app](https://railway.app): **New Project → Deploy from GitHub repo** y elige el repo.
3. Railway detecta Node, ejecuta `npm install` (compila `better-sqlite3`) y `npm start`.
4. **Networking → Generate Domain** para obtener la URL pública (`https://<algo>.up.railway.app`).
5. Variables (opcional): `SESSION_SECRET` a un valor aleatorio. `PORT` **no** hace falta: Railway
   lo inyecta y la app lo lee de `process.env.PORT`.

### Opción B — Railway CLI (sin repo)

```bash
npm i -g @railway/cli
railway login
railway init          # crea el proyecto
railway up            # sube y despliega el directorio actual
railway domain        # genera la URL pública
```

### Notas de despliegue

- **Puerto:** la app usa `process.env.PORT`. No lo fijes manualmente en Railway.
- **SQLite en Railway:** el sistema de archivos del contenedor es efímero. Como la base se
  re-siembra en cada arranque, esto es lo deseado para un target de pruebas (no necesita
  volumen persistente).
- **Build nativo:** `better-sqlite3` compila en el build de Railway sin problema (tiene
  toolchain y red). Si prefieres evitar el build nativo por completo, puedes sustituirlo por el
  módulo integrado `node:sqlite` (Node 22+) — la API `.prepare().get()/.all()/.run()` es casi
  idéntica.
- **Apágalo al terminar:** borra el deployment o el proyecto cuando acabes el escaneo.

---

## Cómo lanzar tu escáner

Apunta tu herramienta automatizada a la URL desplegada. Para maximizar el descubrimiento,
proporciónale sesión autenticada (cookie `sid` tras hacer `POST /api/auth/login`) porque casi
toda la superficie vulnerable está detrás de autenticación. En `ATTACK_GUIDE.md` tienes, para
cada endpoint, el vector exacto, un PoC con `curl` y la razón por la que suele evadir la
detección automática.

## Mapa rápido de vulnerabilidades

| # | Clase | Endpoint principal |
|---|-------|--------------------|
| 1 | IDOR ofuscado (dependiente de estado) | `POST /api/reports/open` → `PATCH /api/reports/scope` → `GET /api/reports/render` |
| 2 | Race condition (sin lock transaccional) | `POST /api/coupons/redeem`, `POST /api/wallet/transfer` |
| 3 | Blind SSRF (metadatos de nube) | `POST /api/webhooks`, `POST /api/webhooks/test` |
| 4 | Mass Assignment | `PUT /api/users/me` |
| 5 | Prototype Pollution → escalada | `POST /api/settings` → `GET /api/admin/metrics` |
| 6 | Deserialización insegura → RCE | `POST /api/session/restore` |
| 7 | HTTP Parameter Pollution | `GET /api/accounts/balance` |
| 8 | Fallo lógico financiero | `POST /api/checkout/cart` · `/receipt` |
| 9 | SQLi ciega basada en tiempo | `GET /api/transactions?sort=` y header `X-Forwarded-For` |
| 10 | Bypass de filtro SSRF (redirección/rango) | `POST /api/documents/fetch` |
| 11 | XXE (lectura de archivos + OOB ciego) | `POST /api/documents/import-xml` |
| 12 | Prototype Pollution → RCE | `POST /api/settings` → `POST /api/exports/run` |
| 13 | SSTI → RCE | `POST /api/templates/preview` |
| 14 | JWT: alg:none + confusión de clave RS256→HS256 | `POST /api/auth/token`, `GET /api/auth/jwks`, `GET /api/v2/admin` |
| 15 | Reset de contraseña: Host poisoning + token predecible | `POST /api/auth/forgot` · `/api/auth/reset` |
| 16 | CORS mal configurado (refleja origin + credenciales) | cualquier endpoint (cabecera `Origin`) |
| 17 | Session fixation | `POST /api/auth/login` (cookie `sid` preexistente) |
| 18 | SQLi de segundo orden | `PUT /api/users/me` (nickname) → `GET /api/reports/summary` |
| 19 | XSS almacenado ciego (dispara en admin) | `POST /api/support` → `/admin.html` |
| 20 | Inyección de operadores estilo NoSQL (rompe scope por owner) | `POST /api/search/invoices` |
| 21 | Web cache poisoning (input no-keyed: `X-Forwarded-Host`) | `GET /api/status/summary` |
| 22 | JWT `kid` path traversal + OAuth open redirect | `GET /api/v2/admin` (kid) · `GET /api/auth/authorize` |
| 23 | Refund double-spend (lógica de negocio + race fino) | `POST /api/billing/charge` → `POST /api/billing/refund` |

Total: **23 vulnerabilidades** (las 19 originales + 4 del set extendido v1.5).

---

## Instrumentación para entrenar un escáner

El lab incluye herramientas para medir, de forma reproducible, cuántas vulnerabilidades
detecta y **verifica** un escáner automatizado (p. ej. un motor de pentest autónomo):

- **`truth.json`** — *ground truth* machine-checkable: por cada vuln, su clase, endpoints,
  cadena de explotación (PoC) y la señal observable que confirma que disparó.
- **Colaborador OOB interno** (`/api/oob/token`, `/api/oob/hits/:token`, colector en
  `/oob/:token`) — listener out-of-band tipo interactsh/Collaborator dentro del propio lab,
  para verificar clases **ciegas** (SSRF, XXE OOB, XSS almacenado) sin infraestructura externa.
- **`tools/coverage.js`** — corre un PoC de referencia por cada vuln contra el lab en marcha,
  comprueba la señal de `truth.json`, imprime una tabla `PASS/FAIL/SKIP` y un marcador
  `X / 23 verificadas`, y escribe `coverage-report.json` (diff antes/después para CI).

```bash
npm start                                   # arranca el lab en :3000
node tools/coverage.js http://localhost:3000
# -> VERIFIED 23 / 23
```

> Nota OOB: el colaborador interno verifica SSRF/XXE/deserialización ciegos por callback.
> Para la RCE por `execSync` (#12), `coverage.js` usa un marcador en disco porque `execSync`
> **bloquea** el event loop del propio server (deadlock con un OOB *interno*); contra un OOB
> **externo** ese callback también funciona.
