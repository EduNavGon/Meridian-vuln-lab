# Brief para Cursor — Elevar la detección de Vex Raptor contra Meridian Ledger v1.5

> Pega TODO lo que hay debajo de la línea como primer mensaje en Cursor (modo Agent/Composer),
> con **el repositorio de Vex Raptor** abierto (el escáner — NO el lab). Antes, rellena los dos
> campos entre `<< >>`.

---

## ROL

Eres ingeniero senior de seguridad ofensiva y de plataformas de scanning. Vas a modificar el
**motor Vex Raptor** (nuestro producto de pentest autónomo; DigitalOcean `/home/deploy/vex-raptor`,
servicios `vex-raptor` + `worker`, v1.4.1) para que **descubra y verifique con PoC** el máximo de
23 vulnerabilidades de un lab deliberadamente vulnerable. Hoy detecta ~1/23. Meta: **≥15/23
verificadas**.

## REGLAS (estrictas)

- Lee PRIMERO la arquitectura real del motor (fases del pipeline, crawl, inyección de payloads,
  manejo de auth/sesión, generación de findings). No asumas nada.
- Verifica cada afirmación contra el código real. Si algo no existe, dilo — no lo inventes.
- Cambios pequeños, con tests, reversibles. Nada que rompa producción sin flag.
- No degrades los detectores pasivos actuales (cabeceras, TLS, puertos): son válidos, solo de bajo valor.

## EL TARGET (lab)

- **Repo del lab:** https://github.com/EduNavGon/Meridian-vuln-lab — clónalo o léelo.
- **URL desplegada:** `<< PON AQUÍ TU URL, p. ej. https://web-production-xxxx.up.railway.app >>`
- **Login (API, JSON):** `POST /api/auth/login` con `{"email","password"}` → cookie `sid`
  (httpOnly, sameSite=lax). Es una SPA en `/`, no hay página `/login`.
- **Credenciales:** `alice@meridian.io / Password123!` · `bob@meridian.io / M3ridian!Bob2026`.
- **Superficie de API:** está en texto plano dentro del bundle `/app.js` y sus source maps `.map`.

### Archivos del lab que TÚ (Cursor) puedes leer para construir los detectores

Estos son tu material de desarrollo. **NO se los pases a Raptor como input en runtime** (ver
METODOLOGÍA):

- `ATTACK_GUIDE.md` — PoC en curl y explicación de cada una de las 23.
- `truth.json` — oráculo machine-readable: por vuln, `id`, clase, endpoints, cadena y **señal esperada**.
- `VULNS.md` — índice código ↔ guía ↔ truth por número.
- `tools/coverage.js` — corre un PoC de referencia por vuln (demuestra que el lab está vivo: 23/23).
- `src/routes/oob.js` — colaborador OOB interno del lab (para validar clases ciegas sin infra externa).

## METODOLOGÍA (crítica — evita falsos positivos)

Dos modos, NO los mezcles:

- **Desarrollo (tú, Cursor):** puedes leer `ATTACK_GUIDE.md` y `truth.json` para escribir la
  lógica de cada detector.
- **Evaluación (Raptor en runtime):** el motor corre **a ciegas**, solo con la URL + credenciales.
  Debe *descubrir* por sí mismo. Si le inyectas `truth.json`/`ATTACK_GUIDE` como entrada, no está
  detectando: está copiando, y el score sería falso.

**Scoring:** tras cada corrida de Raptor, mapea sus findings (por clase + endpoint) a los `id` de
`truth.json` y cuenta cuántos detectó **y verificó con PoC**. Si no existe, crea un pequeño script
`tools/score_against_truth.js` que lea el reporte de Raptor y `truth.json` y saque `X/23`. Ojo:
`coverage.js` NO es el scorer de Raptor — es la prueba de que las 23 están vivas en el deploy y la
fuente de PoCs de referencia.

## ROADMAP DE CAPACIDADES (orden por dependencia)

**Fase 1 — ARCH-1: descubrimiento de superficie (prerrequisito de todo).**
Parsear bundle(s) JS + source maps para extraer rutas `\/api\/[\w/.-]+`, métodos y campos de body.
Enumerar/confirmar cada endpoint con la sesión autenticada. Publicar un **inventario de endpoints**
en el estado compartido del pipeline (el `[MEMORY]`/OODA que ya usáis). Sin esto, nada dispara.

**Fase 2 — inyección y estado (sobre el inventario).**
Motor **stateful** (chains de N peticiones en la misma sesión + correlación fuente→sink). Oráculos
**diferencial**, **de tiempo** (muestreo estadístico) y **de concurrencia**. Inyección consciente de
codificación (claves `__proto__`/`constructor.prototype`, cuerpos XML/DTD, blobs Base64). Cliente
HTTP que: mantiene cookies, permite NO seguir redirects (bypass SSRF), duplica parámetros (HPP) y
envía cabeceras arbitrarias (`X-Forwarded-For`, `X-Forwarded-Host`, `Origin`).

**Fase 3 — OOB-LIVE: colaborador out-of-band propio de Raptor.**
Servidor OOB (tipo interactsh/Collaborator) con dominio propio, token único por prueba y correlación
hit↔petición. Desbloquea SSRF ciego, bypass SSRF, XXE OOB y XSS almacenado ciego. (El lab trae un OOB
interno para que valides tu lógica antes de montar el tuyo.)

**Transversal — verificación de PoC.** Cada finding intenta confirmarse (hit OOB, retardo medible,
lectura cross-tenant, token forjado con 200, etc.). Degrada a `unverified/info` lo no confirmado.
Ningún Critical/High sin un artefacto de PoC comprobable.

## LAS 23 (vector → oráculo) — resumen; el detalle está en ATTACK_GUIDE.md / truth.json

1 IDOR stateful (open→scope→render) · 2 Race cupón (concurrencia) · 3 Blind SSRF (OOB) ·
4 Mass assignment · 5 Prototype pollution→privesc · 6 Deserialización→RCE (OOB) · 7 HPP ·
8 Lógica de negocio (heurística) · 9 SQLi ciega por tiempo (SQLite, ORDER BY) · 10 Bypass SSRF
(redirect/encoding) · 11 XXE (file + OOB) · 12 Prototype pollution→RCE (execSync) · 13 SSTI→RCE ·
14 JWT alg:none / RS256→HS256 · 15 Reset poisoning + token predecible · 16 CORS refleja origin+creds ·
17 Session fixation · 18 SQLi 2º orden · 19 XSS almacenado ciego (headless) ·
20 NoSQL operator injection · 21 Web cache poisoning · 22 JWT `kid` traversal + OAuth open redirect ·
23 Refund double-spend (lógica + race).

## DEFINITION OF DONE

Re-lanzar el scan **autenticado** y pasar de 1/23 a **≥15/23 verificadas con PoC**. La #8 (lógica
pura) se acepta heurística. Entrega: motor que descubre la API de una SPA, encadena con sesión,
dispara y correlaciona OOB, y verifica PoC — con su plan de remediación por clase.

## FLUJO DE TRABAJO ESPERADO

1. Lee la arquitectura real del motor y **mapea** dónde encajan ARCH-1, los oráculos y los detectores.
2. Propón un **plan por fases** (ARCH-1 → inyección/stateful → OOB) con ficheros a tocar y riesgos.
3. Implementa incrementalmente, con tests, verificando cada detector contra el lab en marcha.
4. Re-lanza el scan y **reporta cobertura** (X/23) antes/después.
5. Documenta lo que quede sin cubrir y por qué.
