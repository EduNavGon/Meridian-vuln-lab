# Índice maestro de vulnerabilidades — Meridian Ledger v1.5

Índice único que enlaza, **por número**, cada vulnerabilidad con: el archivo de código donde
vive (el *sink*), su explicación con PoC en `ATTACK_GUIDE.md`, y su entrada machine-readable en
`truth.json`. Total: **23 vulnerabilidades** (19 originales + 4 del set extendido v1.5).

- **Código** → dónde está el bug (fuente de verdad más cercana; cada archivo tiene un comentario
  de cabecera explicando el fallo).
- **Guía** → sección `## N` en [`ATTACK_GUIDE.md`](./ATTACK_GUIDE.md) (PoC en curl + por qué evade escáneres).
- **truth** → objeto con `"id": N` en [`truth.json`](./truth.json) (endpoints, cadena, señal esperada).
- **check** → cómo se autoverifica en `tools/coverage.js`:
  - `auto` = probado end-to-end por HTTP (leak / privilegio / salida observada).
  - `auto-oob` = clase ciega, confirmada por callback al colaborador OOB interno.
  - `heuristic` = sin firma sintáctica; se detecta por comportamiento (fuzz + invariante).

Última corrida de `tools/coverage.js`: **23/23 verificadas** (fail 0).

---

## Tabla índice

| #  | Clase | Código (archivo → sink) | Guía | check |
|----|-------|--------------------------|------|-------|
| 1  | IDOR ofuscado (stateful) | `src/routes/reports.js` (open→scope→render) | §1 | auto |
| 2  | Race condition (coupon over-redeem) | `src/routes/coupons.js`, `src/routes/wallet.js` | §2 | auto |
| 3  | Blind SSRF (metadata) | `src/routes/webhooks.js` → `src/lib/fetchUrl.js` | §3 | auto-oob |
| 4  | Mass assignment | `src/routes/users.js` (`UPDATABLE` incluye `role`,`is_admin`) | §4 | auto |
| 5  | Prototype pollution → privesc | `src/routes/settings.js` → `src/lib/deepmerge.js` → `src/routes/admin.js` | §5 | auto |
| 6  | Deserialización → RCE | `src/routes/restore.js` → `src/lib/unserialize.js` (`eval`) | §6 | auto-oob |
| 7  | HTTP Parameter Pollution | `src/routes/accounts.js` (`first()` vs `last()`) | §7 | auto |
| 8  | Lógica de negocio | `src/routes/checkout.js` (qty negativa / saltar `/pay`) | §8 | heuristic |
| 9  | SQLi ciega por tiempo | `src/routes/transactions.js` (`ORDER BY`), `src/audit.js` (`X-Forwarded-For`) | §9 | auto |
| 10 | Bypass filtro SSRF | `src/routes/documents.js` → `src/lib/ssrfGuard.js` (redirect/encoding) | §10 | auto-oob |
| 11 | XXE (file read + OOB) | `src/routes/documents.js` → `src/lib/xml.js` (entidades SYSTEM) | §11 | auto / auto-oob |
| 12 | Prototype pollution → RCE | `src/routes/settings.js` → `src/lib/deepmerge.js` → `src/routes/exports.js` (`execSync`) | §12 | auto-oob* |
| 13 | SSTI → RCE | `src/routes/templates.js` → `src/lib/template.js` (`new Function`) | §13 | auto |
| 14 | JWT alg:none / RS256→HS256 | `src/lib/jwt.js` → `src/routes/token.js`, `src/routes/v2.js` | §14 | auto |
| 15 | Reset poisoning + token predecible | `src/routes/password.js` (`X-Forwarded-Host`, `md5`) | §15 | auto |
| 16 | CORS refleja Origin + creds | `server.js` (middleware CORS) | §16 | auto |
| 17 | Session fixation | `src/routes/auth.js` → `src/session.js` (`createSession` reusa token) | §17 | auto |
| 18 | SQLi de segundo orden | `src/routes/users.js` (nickname) → `src/routes/reports.js` (`/summary`) | §18 | auto |
| 19 | XSS almacenado ciego | `src/routes/support.js` → `src/routes/admin.js` (`/tickets`) → `public/admin.html` (`innerHTML`) | §19 | auto-oob** |
| 20 | NoSQL operator injection | `src/routes/search.js` (`$ne`/`$or` → SQL) | §20 | auto |
| 21 | Web cache poisoning | `src/routes/status.js` (cache no-keyed + `X-Forwarded-Host`) | §21 | auto |
| 22 | JWT `kid` traversal + OAuth open redirect | `src/lib/jwt.js` (`kid`→disco), `src/routes/oauth.js` (`redirect_uri`) | §22 | auto |
| 23 | Refund double-spend (lógica + race) | `src/routes/billing.js` (charge→refund no atómico) | §23 | auto |

---

## Los 3 casos con verificación automática más débil (no son falsos — son reales)

Estos existen a nivel de código igual que el resto; lo único distinto es cómo se **prueba** de
forma automática. Documentados aquí para que la herramienta no cante "verificado" donde solo
llegó al sink:

- **#8 — Lógica de negocio** (`heuristic`). Cada request es válida por separado; el fallo es una
  invariante económica. Se detecta por fuzz numérico (qty negativa → subtotal negativo) y de
  secuencia (saltar `/pay`), no por una firma. Es la más dura para cualquier escáner.
- **#12 — Prototype pollution → RCE** (`auto-oob*`). El comando inyectado **sí se ejecuta**
  (confirmado con marcador en disco). El asterisco: con un OOB *interno* hay deadlock porque
  `execSync` bloquea el event loop del propio server; para confirmar por **callback** hace falta
  un colaborador OOB **externo**.
- **#19 — XSS almacenado ciego** (`auto-oob**`). El sink es real: `public/admin.html` inserta
  `t.body` con `innerHTML` **sin escapar** (línea ~34), así que el `<img onerror>` ejecuta en la
  sesión del admin. El doble asterisco: `coverage.js` prueba que el payload se **almacena sin
  escapar y llega al admin**; confirmar la **ejecución** JS requiere un navegador headless.

---

## Cómo verificarlo tú mismo

```bash
npm install                                   # nativo en Linux/Railway; en el sandbox usa el adaptador node:sqlite
npm start                                      # lab en http://localhost:3000 (reseed limpio en cada arranque)
node tools/coverage.js http://localhost:3000   # -> VERIFIED 23 / 23 ; escribe coverage-report.json
```

Cada PoC individual en curl está en `ATTACK_GUIDE.md` bajo la sección `## N` correspondiente.
