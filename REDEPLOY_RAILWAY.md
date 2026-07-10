# Redeploy Railway — Meridian Ledger (benchmark heal)

> Objetivo: dejar la instancia Railway en estado **fresco y medible** para el recall de Vex Raptor.
> Contexto: `src/db.js` hace `DROP TABLE` + reseed **en cada boot** (no hay volumen declarado en `railway.json`), así que **reiniciar el proceso = base de datos limpia**. Un redeploy además publica código nuevo (p. ej. `POST /api/coupons/reseed`).

## Por qué hace falta

La instancia compartida se degrada entre reinicios porque los escaneos mutan el estado:

- **Cupones agotados** — `WELCOME50: 0`, `LOYALTY25: -9` (over-redeem ya explotado). La race #2 necesita inventario positivo (`WELCOME50 = 1`).
- **alice drifteada** — su password se cambió en algún test de reset (#15); deja de coincidir con `truth.json` → `login 401`.
- **`/api/coupons/reseed` → 404** — el build desplegado es **anterior** al commit que añadió `src/routes/coupons.js` `/reseed`. Existe en el repo; falta desplegarlo.

Un **redeploy** arregla las tres cosas de golpe: reconstruye con el código actual (incluye `/reseed`) y reinicia el proceso → `seed()` deja alice + cupones frescos.

> Distinción útil:
> - Solo **drift** (cupones/alice) → basta un **restart** (re-corre `seed()`).
> - Build **stale** (falta `/reseed`) → hace falta **redeploy** (rebuild desde el código actual).
> - Como aquí hay ambos, haz **redeploy** (que también reinicia).

## Pasos de redeploy

Elige UNA vía (según cómo esté conectado el servicio en Railway):

**A. Git (si el servicio despliega desde GitHub/Gitea):**
```
git add src/routes/coupons.js REDEPLOY_RAILWAY.md
git commit -m "LAB-22: reseed clock-skew window + redeploy doc"
git push origin main    # rama que Railway observa
```
Railway detecta el push y redespliega solo.

**B. Railway CLI:**
```
railway up
# o forzar reinicio del servicio activo:
railway redeploy
```

**C. Dashboard Railway:**
Proyecto → servicio `meridian` → **Deployments** → menú `⋯` del último deploy → **Redeploy**
(o **Restart** si solo quieres reseedear sin cambiar código — pero necesitas Redeploy para publicar `/reseed`).

## Config a confirmar en Railway

- **`LAB_MODE` NO debe ser `'0'`.** Con `LAB_MODE='0'`, `/api/coupons/reseed` responde 404 a propósito. Déjalo sin definir o `LAB_MODE=1`.
- `startCommand`: `node server.js` (ya en `railway.json` y `Procfile`).
- Node 20 (`.nvmrc`).

## Verificación post-redeploy

```
BASE=https://web-production-d3467.up.railway.app

# 1. salud
curl -s $BASE/healthz

# 2. alice fresca (debe dar 200 y set-cookie sid)
curl -s -i -X POST $BASE/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@meridian.io","password":"M3ridian!Alice2026"}' | head -5

# 3. reseed vivo (token de minuto actual, salt meridian)
TOKEN=$(node -e "const c=require('crypto');const m=Math.floor(Date.now()/60000);console.log(c.createHash('md5').update('coupons:'+m+':meridian').digest('hex').slice(0,16))")
curl -s -X POST $BASE/api/coupons/reseed -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\"}"
# esperado: {"ok":true,"reseeded":[{"code":"WELCOME50","remaining_uses":1},...]}
```

Oráculo del propio lab (opcional, mide 23/23 real):
```
node tools/coverage.js $BASE
```

Luego re-corre el smoke de Vex Raptor (repo Vex-Raptor) y lee `data/meridian_smoke_summary.json`.

## Qué recupera esto (y qué no)

- **#2 Coupon race → recuperado** (inventario fresco + `/reseed` vivo). Railway **20 → 21**.
- **#15 Reset predecible → NO es defecto del lab.** El oráculo (`tools/coverage.js` check 15) lo verifica contra un lab fresco vía token forjado sobre **bob**. En Railway lo falla el **motor Vex Raptor**, no el lab: con alice sana pasa a ser identidad *primary* y el reset-victim queda "preservado" (no se lockea al scanner) → se salta el forge. Para el 22.º hay que hacer que el smoke de Railway corra **bob-primary + admin** (como el local `local_bob_admin`), de modo que alice sea víctima no-preservada. **Eso es cambio en Vex-Raptor, fuera de LAB-22.**
- **#21 Web cache poisoning → platform-bound.** La caché de borde compartida de Railway no refleja el header dentro del TTL (`summary_cache_stayed_warm`). El lab lo implementa bien (el oráculo lo verifica local con caché aislada). Es el 23.º esperado.
