# Nexum — Session Log

---

## Session 2026-05-10 — Sprint 0 Parte 1: Core Engine

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| 1 | `core/ingestor.py` + fixtures sintéticos | ✅ |
| 2 | `core/rules/base.py` + dataclass `Finding` + NEXUM-001 `AuthLeakageRisk` | ✅ |
| 3 | NEXUM-002 `DestructiveAmbiguity`, NEXUM-003 `UnboundedScope`, NEXUM-004 `IdempotencyMissing`, NEXUM-005 `SchemaVolatility` | ✅ |
| 4 | `core/engine.py` | ✅ |
| 5 | Checkpoint pytest — suite completo contra ambos fixtures | ✅ |
| 6 | `core/scorer.py` — fórmula CRITICAL=25 HIGH=10 MEDIUM=5 LOW=1, cap 100, tiers | ✅ |
| 7 | `manifest/generator.py` — Trust Manifest draft JSON | ✅ |
| 8 | `cli.py` — comando `nexum scan <archivo>` con typer | ✅ |

**Test suite: 92/92 en verde.**

### Decisiones de diseño

**PDF pausado (Bloque 9):**
Pospuesto hasta tener al menos un scan contra API real. Generar layout sobre fixtures
sintéticos no aporta feedback útil sobre qué información debe verse primero.

**NEXUM-003 + MCP — silencio limpio por diseño:**
La regla solo evalúa DELETE y PATCH. Los tools MCP normalizados a POST son filtrados
en la primera línea del bucle. Fijado con test explícito para evitar regresiones.

**CLI — subcomando `scan` requiere `@app.callback()`:**
Con un único `@app.command()`, typer expone el comando directamente como `nexum <file>`
en lugar de `nexum scan <file>`. El callback vacío activa la estructura de subcomandos.

---

## Session 2026-05-10 — Sprint 0 Parte 2: Primera API Real + PDF

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| A | Fixture real: `tests/fixtures/real_twilio_v2010.json` (1.8 MB) | ✅ |
| B | Scan Twilio v2010: 62 findings, score 100/100, Tier 2 | ✅ |
| C | `data/findings_log.jsonl`: 65 entradas iniciales | ✅ |
| 9 | `report/pdf_generator.py` + comando `nexum report` | ✅ |

### Hallazgos reales — Twilio v2010

| Regla | Severity | Count |
|-------|----------|-------|
| NEXUM-004 IdempotencyMissing | HIGH | 62 |

NEXUM-001/002/003/005 no dispararon — Twilio usa HTTP Basic Auth + AccountSid en path,
sin query string credentials, sin endpoints de borrado sin ID, sin additionalProperties.

### Deuda técnica registrada
- **TD-002:** manifest generator no lee `securitySchemes` → `required_headers` vacío
- **TD-003:** `immutable_fields` extractor no cubre convención `x-twilio.pii` ni `readOnly` en OpenAPI 3.0
- **TD-004:** Score "100" se renderizaba como "10 0" en reportlab — **FIXED**
- **TD-005:** Paths largos en Top Findings sin truncado — **FIXED**
- **TD-006:** `truncate_path` corta en posición de carácter, no en límite de segmento `/` — cosmético, pendiente

---

## Session 2026-05-10 — Sprint 0 Parte 3: GitHub REST API

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| A | Fixture real: `tests/fixtures/real_github.json` (11.9 MB, 500+ endpoints) | ✅ |
| B | Scan GitHub REST API: 404 findings, score 100/100, Tier 2 | ✅ |
| C | PDF fix TD-004: score frame 3.2 cm → 4.5 cm | ✅ |
| D | PDF fix TD-005: `truncate_path(max_chars=80)` | ✅ |
| E | Tabla "Findings by Rule" añadida al final de Página 1 | ✅ |
| F | `findings_log.jsonl`: 72 entradas totales | ✅ |

### Hallazgos reales — GitHub REST API

| Regla | Severity | Count |
|-------|----------|-------|
| NEXUM-001 AuthLeakageRisk | CRITICAL | 3 |
| NEXUM-002 DestructiveAmbiguity | CRITICAL | 4 |
| NEXUM-003 UnboundedScope | HIGH | 7 |
| NEXUM-004 IdempotencyMissing | HIGH | 382 |
| NEXUM-005 SchemaVolatility | MEDIUM | 8 |

Las 5 reglas han disparado contra al menos una spec real. Objetivo de calibración cumplido.

### Decisiones de diseño

**Tabla "Findings by Rule" — Opción A con variante:**
Añadida al final de Página 1. Solo aparece si más de una regla disparó.
Columnas: Rule ID | Rule Name | Findings | Severity. Ordenada CRITICAL → LOW.

### Deuda técnica registrada
- **TD-007:** Score display "100/ 100" sin espacio — cosmético, pendiente
- **TD-010:** NEXUM-002 `human_explanation` no distingue borrado real vs. revocación implícita
- **TD-011 (original):** NEXUM-001 no diferencia auth-principal-en-query (CRITICAL) de auth-legacy-opcional (HIGH)
- **TD-012:** PDF Página 2 con >100 findings de una regla ilegible — agrupar por resource family pendiente

---

## Session 2026-05-11 — Renombrado Pact → Nexum + Web Interface

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| 1 | Renombrado completo: `pact` → `nexum`, `PACT-00X` → `NEXUM-00X` | ✅ |
| 2 | `NexumIngestError`, `nexum_risk_score`, `nexum scan` | ✅ |
| 3 | grep `PACT` → 0 hits en codebase | ✅ |
| 4 | `web/app.py` (FastAPI) + `static/index.html` (HTML vanilla) | ✅ |
| 5 | 13 tests nuevos de web interface | ✅ |
| 6 | Commit `97c5a4e` — feat: add web interface | ✅ |

**Test suite: 105/105 en verde.**

### Decisiones de diseño

**Web interface — cero persistencia:**
Los specs subidos se procesan en memoria y se descartan. Sin auth, sin base de datos,
sin historial. El PDF se devuelve como descarga directa.

**`tempfile delete=True`:**
Correcto en Linux/Mac. Edge case en Windows (archivo no legible mientras abierto).
No aplica porque Railway corre Linux.

---

## Session 2026-05-11 — Repos Públicos + Dominio

### Completado

| Artefacto | Estado |
|---|---|
| Dominio `getnexum.dev` registrado | ✅ |
| Repo público `nexum` en GitHub | ✅ |
| Repo público `nexum-trust-manifest` en GitHub | ✅ |
| Trust Manifest v1.0 spec publicada (5 archivos) | ✅ |
| `.gitignore` corregido post-renombrado | ✅ |
| Fixtures reales excluidos del repo público | ✅ |
| Commit `c492c6a` — fix gitignore, remove untracked artifacts | ✅ |

### Contenido de nexum-trust-manifest
- `README.md` — qué es, por qué existe, cómo se lee
- `spec/trust-manifest-v1.0.json` — JSON Schema formal
- `examples/tier0-example.json` — API de solo lectura, score 0
- `examples/tier1-example.json` — API con mutaciones, score 50
- `examples/tier2-example.json` — GitHub REST API real, score 100

---

## Session 2026-05-12 — Deploy Railway + Fixes Pre-Distribución

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| 0 | Auditoría grep "pact" — 0 hits confirmados | ✅ |
| 1 | Limpieza residuos "pact" en codebase | ✅ |
| 2 | Disclaimer footer en PDF (todas las páginas, 7pt, gris) | ✅ |
| 3 | `CLAUDE.md` actualizado — separación Scanner Risk Score vs Runtime Block Score | ✅ |
| 4 | Smoke test completo: 105/105, PDF con footer, grep pact = 0 | ✅ |
| 5 | Deploy en Railway — uvicorn corriendo en puerto 8080 | ✅ |
| 6 | `www.getnexum.dev` verificado y respondiendo 200 | ✅ |
| 7 | `getnexum.dev` verificado | ✅ |
| 8 | Commit `d0f6ef1` + `23f6d67` pusheados a origin/main | ✅ |

---

## Session 2026-05-12 — Fixes TD-005/TD-008 + MCP Scans

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| 1 | TD-005: MCP annotations propagadas al normalizador | ✅ |
| 2 | `readOnlyHint: true` → skip en NEXUM-004 | ✅ |
| 3 | `idempotentHint: true` → skip en NEXUM-004 | ✅ |
| 4 | Heurístico token matching expandido | ✅ |
| 5 | Keywords `status`, `diff`, `log` añadidas a `_READ_KEYWORDS` | ✅ |
| 6 | TD-008: `git_reset` explanation corregida | ✅ |
| 7 | 9 falsos positivos eliminados, 2 falsos negativos corregidos | ✅ |

### Scans MCP realizados

| MCP Server | Findings | Falsos positivos | Distribuible |
|---|---|---|---|
| Filesystem MCP | 5 | 3 pre-fix, 0 post-fix | ✅ |
| Git MCP | 11 | 6 pre-fix, ~2 post-fix | ⚠️ Con nota |
| Slack MCP | 2 | 0 | ✅ |
| SQLite MCP | 3 | 0 (write_query es mutación real) | ✅ |

### Deuda técnica registrada
- **TD-008:** `git_reset` human_explanation corregida — **FIXED**
- **TD-009 (nuevo):** Execution Frequency Weighting — ponderar findings por probabilidad de uso real
- **TD-010 (nuevo):** Domain-specific `manual_review_required` — campos genéricos vs. específicos de dominio

---

## Session 2026-05-12 — DigitalOcean Scan + Adversarial Validator

### Completado

| Artefacto | Estado |
|---|---|
| Scan DigitalOcean API: 221 findings, score 100/100, Tier 2 | ✅ |
| PDF `digitalocean_final.pdf` generado post-fix | ✅ |
| Post de X publicado y eliminado (ver incidente abajo) | ⚠️ |
| `NEXUM_ADVERSARIAL_VALIDATOR_V2.md` creado y subido al proyecto | ✅ |
| Primera ejecución del Adversarial Validator contra DigitalOcean PDF | ✅ |

### Incidente: Post de X eliminado

**Causa:** El Adversarial Validator v2.0 detectó en primera ejecución que 2 de 5
findings CRITICAL eran falsos positivos:

| Finding | Veredicto | Evidencia |
|---------|-----------|-----------|
| DELETE /v2/registry | ✅ Válido (endpoint deprecated) | doctl: "permanently deletes, irreversible" |
| DELETE /v2/kubernetes/registry | ❌ Falso positivo | Docs: "Removes container registry support from cluster" — desvinculación |
| DELETE /v2/kubernetes/registries | ❌ Falso positivo | Docs: "managing DOCR integration with Kubernetes clusters" — desvinculación |
| DELETE /v2/droplets | ✅ Válido | Borrado real por tag, irreversible |
| DELETE /v2/volumes | ✅ Válido | Borrado real por nombre, irreversible |

**Score real post-corrección:** 50/100, Tier 1 — MODERATE RISK (no 100/100 Tier 2)

**Acción tomada:** Post eliminado a 10 impresiones. Sin impacto de credibilidad.

**Aprendizaje:** El Adversarial Validator v2.0 funcionó correctamente —
detectó el problema antes de que lo hiciera un cliente real.

### Deuda técnica registrada

**TD-011 (redefinido):** NEXUM-002 no distingue entre DELETE de borrado real
y DELETE de desvinculación de recursos.
- Casos confirmados: `/v2/kubernetes/registry` y `/v2/kubernetes/registries`
- Causa raíz: el scanner analiza método HTTP y ausencia de path param,
  pero no la semántica de la operación
- Solución propuesta: protocolo de verificación manual en Adversarial Validator
  Ángulo 4 — no heurística automática (requeriría NLP)
- Prioridad: Alta — afecta credibilidad de findings CRITICAL

**Protocolo de verificación NEXUM-002 añadido al Validator:**
Para cada finding NEXUM-002, buscar en docs oficiales el verbo exacto:
- "deletes", "destroys", "permanently removes" → finding válido
- "removes support", "detaches", "unlinks", "disassociates" → falso positivo
- "deprecated" → válido con nota de contexto

---

## Tech Debt — Backlog Completo

| ID | Descripción | Prioridad | Sprint | Estado |
|----|-------------|-----------|--------|--------|
| TD-001 | NEXUM-004 heurístico de nombres frágil — tools como `remove_record` no detectadas | Baja | 3 | Abierto |
| TD-002 | manifest generator no lee `securitySchemes` → `required_headers` vacío | Media | 2 | Abierto |
| TD-003 | `immutable_fields` no cubre `x-twilio.pii` ni `readOnly` en OpenAPI 3.0 | Media | 2 | Abierto |
| TD-004 | Score "100" se renderizaba como "10 0" en reportlab | — | — | **FIXED** |
| TD-005 | MCP annotations no propagadas — falsos positivos en NEXUM-004 | Alta | 1 | **FIXED** |
| TD-006 | `truncate_path` corta en carácter, no en límite de segmento `/` | Baja | 3 | Abierto |
| TD-007 | Score display "100/ 100" sin espacio — cosmético | Baja | 3 | Abierto |
| TD-008 | `git_reset` human_explanation incorrecta | Alta | 1 | **FIXED** |
| TD-009 | Execution Frequency Weighting — reducir ruido NEXUM-004 en APIs grandes | Alta | 2 | Abierto |
| TD-010 | Domain-specific `manual_review_required` — campos genéricos vs. dominio | Media | 2 | Abierto |
| TD-011 | NEXUM-002 no distingue borrado real vs. desvinculación — requiere verificación manual | Alta | 2 | Abierto |

---

## Candidatos NEXUM-006+

| ID tentativo | Nombre | Detectaría | Evidencia real |
|---|---|---|---|
| NEXUM-006 | CredentialInPath | AccountSid u otros identificadores sensibles en URL path | Twilio v2010 |
| NEXUM-007 | LegacyAuthFallback | Auth opcional en query string vs. auth principal en header | GitHub Packages |
| NEXUM-008 | CascadeDeleteRisk | Parámetros `cascade:true`, `force:true`, `recursive:true` en spec | Pendiente |
| NEXUM-009 | RateLimitAbsent | Endpoints sin rate limiting declarado en spec | Pendiente |

**Regla de implementación:** Ningún candidato se construye sin aparición confirmada
en `findings_log.jsonl`. La evidencia empírica es el árbitro.

---

## Estado Actual del Proyecto

```
Tests:          105/105 en verde
CLI:            nexum scan <archivo> | nexum report <archivo> --output report.pdf
Web:            https://getnexum.dev (live, Railway)
Repo principal: github.com/mehdibelckadi-dev/nexum
Trust Manifest: github.com/mehdibelckadi-dev/nexum-trust-manifest
findings_log:   72 entradas reales
PDFs validados: GitHub REST, Slack MCP, Filesystem MCP (post-fix)
PDFs pendientes: DigitalOcean (regenerar con --exclude-path post TD-011)
```

## Próxima Sesión

1. Implementar `--exclude-path` en CLI para excluir falsos positivos confirmados
2. Regenerar PDF DigitalOcean sin los 2 findings falsos positivos
3. Ejecutar Adversarial Validator v2.0 contra PDF regenerado
4. Republicar post de X con score y copy corregidos
5. Iniciar outreach personalizado con FEEDBACK_LOG
