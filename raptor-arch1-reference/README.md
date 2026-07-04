# ARCH-1 — Descubrimiento de superficie de API (referencia para Vex Raptor)

Implementación de referencia de la **Fase 1** del roadmap de Raptor: el módulo que
convierte "API = not found" en un **inventario de endpoints** que alimenta a todos los
módulos de ataque. Es dependency-free (solo `http`/`https` de Node) para que se porte
limpio al motor.

## Qué hace

Combina dos fuentes, porque ninguna basta sola:

1. **Parseo del bundle** — extrae literales `/api/...` (+ método + campos de body/query)
   del JS servido. Consigue gratis las rutas que usa la UI (~20).
2. **Sondeo activo** — un wordlist genérico de API + expansión por prefijo, **confirmado
   contra el target** con la sesión autenticada. Esto encuentra las rutas *ocultas* que el
   bundle nunca referencia (admin, documents, exports, templates, v2, search, billing,
   oauth, `reports/scope`, …).

**Truco de detección** para esta clase de SPA en Express: los GET desconocidos caen en el
catch-all y devuelven el HTML de la SPA (200 text/html); los POST/PUT/PATCH desconocidos
devuelven 404. Por tanto una ruta es real cuando una prueba devuelve JSON, un status de
aplicación (400/401/402/403/405/409) o un 200 no-html — nunca "200 html" ni 404.

## Uso

```bash
node discover.js <baseUrl> <email> <password>
node discover.js http://localhost:3000 alice@meridian.io 'Password123!'
```

Salida: tabla por consola + `endpoints.json` con `{method, path, source, status, bodyFields}`.

## Resultado contra el lab (verificado)

- Parseo de bundle: **20** rutas.
- Total tras sondeo: **43 endpoints**, incluidas TODAS las rutas de ataque ocultas y los
  métodos correctos (detecta `PATCH /api/reports/scope` y `PUT /api/users/me`, que son
  justo los que habilitan el IDOR y el mass-assignment).

## Cómo integrarlo en Raptor

1. Ejecuta ARCH-1 **antes** de cualquier fase de ataque.
2. Publica el array de `endpoints.json` en el estado compartido del pipeline (el
   `[MEMORY]`/OODA que ya usáis).
3. Los detectores de la Fase 2/3 leen sus objetivos de ahí (método + campos), en vez de
   `/`.

## Notas de portabilidad

- El wordlist (`WORDS`) es **genérico** a propósito (nombres REST comunes), no la lista de
  rutas del lab. Así el descubrimiento es honesto: Raptor *descubre*, no copia una respuesta.
- Ajusta `CONCURRENCY` (env) y el nº de métodos si el target es remoto y quieres ir más
  suave. Contra el lab local, ~2.200 candidatos × 4 métodos corren en segundos.
- Para SPAs minificadas reales, añade el parseo de `.map` (ya intenta descargar `<script>.map`).
