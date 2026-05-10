# PACT Session Log

---

## Session 2026-05-10

### Bloques completados

| # | Artefacto | Estado |
|---|---|---|
| 1 | `core/ingestor.py` + fixtures | ✅ |
| 2 | `core/rules/base.py` + `Finding` + PACT-001 `AuthLeakageRisk` | ✅ |
| 3 | PACT-002 `DestructiveAmbiguity`, PACT-003 `UnboundedScope`, PACT-004 `IdempotencyMissing`, PACT-005 `SchemaVolatility` | ✅ |
| 4 | `core/engine.py` | ✅ |
| 5 | Checkpoint pytest — suite completo contra ambos fixtures | ✅ |
| 6 | `core/scorer.py` — fórmula CRITICAL=25 HIGH=10 MEDIUM=5 LOW=1, cap 100, tiers | ✅ |
| 7 | `manifest/generator.py` — Trust Manifest draft JSON | ✅ |
| 8 | `cli.py` — comando `pact scan <archivo>` con typer | ✅ |

**Test suite final: 92/92 en verde, 0.08 s.**

### Decisiones de diseño

**PDF pausado (Bloque 9):**
El PDF se pospone hasta tener al menos un caso de scan contra una API real (Notion o MCP
GitHub). Generar el layout de 2 páginas sobre fixtures sintéticos no aporta feedback útil
sobre qué información necesita verse primero. Se retoma en la próxima sesión inmediatamente
después del scan real.

**PACT-003 + MCP — silencio limpio por diseño:**
La regla solo evalúa DELETE y PATCH. Los tools MCP normalizados a POST son filtrados en la
primera línea del bucle. El comportamiento está fijado con un test explícito
(`test_mcp_fixture_returns_empty_list_without_exception`) para que no regrese en una
refactorización futura.

**CLI — subcomando `scan` requiere `@app.callback()`:**
Con un único `@app.command()`, typer expone el comando directamente como `pact <file>` en
lugar de `pact scan <file>`. El callback vacío activa la estructura de subcomandos sin
añadir lógica.

---

## Session 2026-05-10 — Parte 2: Primera caza real + PDF

### Bloques completados
| # | Artefacto | Estado |
|---|-----------|--------|
| A | Fixture real: pact/tests/fixtures/real_twilio_v2010.json (1.8MB, válido) | ✅ |
| B | Primer scan real: 62 findings PACT-004 HIGH, score 100/100 Tier 2 | ✅ |
| C | data/findings_log.jsonl: 65 entradas (62 findings + 3 analysis_notes) | ✅ |
| 9 | report/pdf_generator.py + comando pact report | ✅ |

### Hallazgos reales encontrados
| API | Regla disparada | Severity | Count |
|-----|----------------|----------|-------|
| twilio_v2010 | PACT-004 IdempotencyMissing | HIGH | 62 |

### Reglas que NO dispararon en Twilio (investigar en Sesión 3)
- PACT-001: Twilio usa HTTP Basic Auth + AccountSid en path, no query string
- PACT-002: No hay endpoints de borrado sin ID específico en esta spec
- PACT-003: No hay DELETE/PATCH sin filtros obligatorios detectados
- PACT-005: No hay additionalProperties: true en schemas de mutación

### Deuda técnica nueva
**TD-002:** manifest generator no lee securitySchemes → required_headers queda vacío  
**TD-003:** immutable_fields extractor no cubre convención x-twilio.pii ni readOnly en OpenAPI 3.0  
**TD-004:** Score "100" se renderiza como "10 0" en reportlab — problema de frame/layout — **fixed**  
**TD-005:** Paths largos en Top Findings sin truncado — necesita recorte con "..." al centro — **fixed**  
**TD-006:** `truncate_path` corta en posición de carácter, no en límite de segmento `/` — el resultado (`...ts/`) carece de contexto para un lector sin conocimiento de la API  

### Candidatos PACT-006+
- PACT-006 CredentialInPath: detectar accountSid u otros identificadores sensibles en URL path

### Próxima sesión: empezar por
1. Investigar por qué PACT-001/002/003/005 no dispararon en Twilio — ¿falsos negativos o spec correcta?
2. Fix TD-004 (score partido) y TD-005 (paths truncados) en el PDF
3. Scan contra Notion API — objetivo: disparar PACT-002 y PACT-005

---

## Session 2026-05-10 — Parte 3: GitHub REST API scan

### Bloques completados
| # | Artefacto | Estado |
|---|-----------|--------|
| A | Fixture real: pact/tests/fixtures/real_github.json (11.9 MB, 500+ endpoints) | ✅ |
| B | Scan GitHub REST API: 404 findings, score 100/100 Tier 2 | ✅ |
| C | PDF fix TD-004: score frame 3.2 cm → 4.5 cm, "100" sin wrap | ✅ |
| D | PDF fix TD-005: `truncate_path(max_chars=80)` en Top Findings y tabla completa | ✅ |
| E | PDF mejora: tabla "Findings by Rule" al final de Página 1 (Opción A con variante) | ✅ |
| F | Append findings_log.jsonl: 5 rule summaries + 2 analysis notes (AN-004, AN-005) | ✅ |

### Hallazgos reales — GitHub REST API
| API | Regla | Severity | Count |
|-----|-------|----------|-------|
| github REST | PACT-001 AuthLeakageRisk | CRITICAL | 3 |
| github REST | PACT-002 DestructiveAmbiguity | CRITICAL | 4 |
| github REST | PACT-003 UnboundedScope | HIGH | 7 |
| github REST | PACT-004 IdempotencyMissing | HIGH | 382 |
| github REST | PACT-005 SchemaVolatility | MEDIUM | 8 |

Objetivo cumplido: PACT-001, PACT-002 y PACT-005 dispararon por primera vez en una API real.
Las 5 reglas han disparado contra al menos una spec real.

### Decisiones de diseño

**GitHub como target preferido sobre Notion:**
La spec de GitHub REST API (11.9 MB, 500+ endpoints) cubre las 5 reglas y ofrece un
volumen suficiente para validar el PDF bajo carga real. Notion API no estuvo disponible
en el endpoint esperado (HTTP 404). GitHub se adopta como fixture canónico de integración.

**Tabla "Findings by Rule" — Opción A con variante:**
Se añade al final de Página 1, después de Top Findings y antes del salto de página.
Condición de aparición: solo si más de una regla disparó (Twilio con una sola regla no
la muestra). Columnas: Rule ID | Rule Name | Findings (right-aligned) | Severity.
Ordenada por severidad CRITICAL → LOW. El objetivo es dar al CISO una vista ejecutiva
del breakdown sin tener que leer la tabla de detalle de Página 2.

### Observaciones de calidad post-scan

**PACT-002 — falso positivo semántico (AN-005):**
`/installation/token DELETE` y `/user/interaction-limits DELETE` son revocaciones de token
y resets de límite del caller autenticado, no borrados de recursos identificados. El engine
detecta correctamente (DELETE sin parámetro de ID), pero `human_explanation` no captura la
semántica de revocación. Candidato a mejorar la explicación, no la regla. → TD-010.

**PACT-001 — inflación de severidad (AN-004):**
Los 3 findings de GitHub Packages usan `"required": false`. El parámetro `?token=` es un
fallback legacy; la auth primaria es por header. La regla detecta correctamente el vector,
pero la severidad debería distinguir auth principal (CRITICAL) de auth legacy opcional
(HIGH). → TD-011.

**PDF — volumen de findings:**
404 findings saturan Página 2. El patrón `...and N more` (máx. 5 filas por regla) contiene
el desbordamiento visual. La tabla "Findings by Rule" en Página 1 mitiga el problema para
el lector ejecutivo. El agrupado por resource family en Página 2 queda pendiente. → TD-012.

### Deuda técnica nueva
**TD-007:** Score display muestra "100/ 100" sin espacio antes de la barra — `LEFTPADDING=0` en la segunda columna de la score table elimina el gap visual  
**TD-010:** PACT-002 `human_explanation` no distingue "borrado de recurso" vs "revocación/reset implícito al caller" — afecta legibilidad para un CISO sin contexto de la API  
**TD-011:** PACT-001 no diferencia auth-principal-en-query (CRITICAL) de auth-legacy-opcional-en-query (debería ser HIGH) — puede inflar severidad  
**TD-012:** PDF Página 2 con >100 findings de una sola regla es ilegible — agrupar por resource family mejoraría señal/ruido  

### Candidatos PACT-006+
- PACT-006 CredentialInPath: AccountSid u otros identificadores sensibles en URL path
- PACT-007 LegacyAuthFallback: separar query-auth opcional/legacy de query-auth principal (surge de TD-011)

---

## Tech Debt

### [TD-001] PACT-004 — Read-only MCP tool detection relies on name heuristic

**File:** `pact/core/rules/idempotency.py` — `_is_mcp_read_only()`  
**Recorded:** 2026-05-10

**Problem:**  
The function skips idempotency checks for MCP tools whose `operationId` contains one of a
fixed set of keywords: `list`, `get`, `read`, `fetch`, `show`, `describe`, `find`, `search`, `query`.

This means tools with semantically equivalent but differently named operations will not be skipped:

| Tool name | Should skip? | Actual behaviour |
|---|---|---|
| `list_files` | Yes | Skipped ✓ |
| `read_file` | Yes | Skipped ✓ |
| `remove_record` | No — destructive | **Skipped incorrectly** ✗ |
| `purge_data` | No — destructive | **Skipped incorrectly** ✗ |
| `fetch_and_delete` | No — destructive | Skipped incorrectly ✗ |

**Root cause:**  
MCP tool definitions carry no machine-readable intent signal beyond the free-text `description`
and the tool `name`. Determining mutability from a name alone is inherently fragile.

**Proposed fix (for scoring multidimensional phase):**  
Introduce an explicit `x-pact-intent` annotation that tool authors can set
(`read` | `write` | `delete` | `idempotent-write`), and fall back to the name heuristic only
when the annotation is absent. Alternatively, inspect the `inputSchema` for the presence of
an `idempotency_key` property as a secondary signal.

**Impact while unfixed:**  
Low. The heuristic under-flags (missed findings), not over-flags (false positives).
A missed idempotency finding is surfaced as HIGH severity, so any slip will be visible
once the scorer is in place.

---

### [TD-006] `truncate_path` — corte en posición de carácter, no en límite de segmento

**File:** `pact/report/pdf_generator.py` — `truncate_path()`  
**Recorded:** 2026-05-10

**Problem:**  
La función actual divide el string en `head = keep // 2` y `tail = keep - head` caracteres,
sin considerar dónde caen los separadores `/`. El resultado puede partir un segmento de path
a la mitad, produciendo tokens sin significado como `...ts/` o `...Sid}/`:

```
/2010-04-01/Accounts/{AccountSid}/SIP/...ts/{CredentialListSid}/Credentials.json
```

Un CISO sin conocimiento de la API de Twilio no puede reconstruir la jerarquía del recurso
a partir del fragmento visible.

**Root cause:**  
Truncado posicional puro. No hay búsqueda de `/` ni hacia la izquierda del punto de corte
del head ni hacia la derecha del punto de corte del tail.

**Proposed fix:**  
Tras calcular `head` y `tail`, buscar el `/` más cercano hacia la izquierda del punto `head`
y el `/` más cercano hacia la derecha del punto `len(path) - tail`, de modo que el corte
coincida siempre con un límite de segmento. Si no existe un `/` en un radio razonable
(p.ej. 10 chars), mantener el corte posicional como fallback.

Resultado esperado para el mismo path:
```
/2010-04-01/Accounts/{AccountSid}/.../CredentialLists/{CredentialListSid}/Credentials.json
```

**Impact while unfixed:**  
Cosmético. El path completo está disponible en el JSON del finding. El truncado al centro
cumple el objetivo primario (no desbordar la columna); solo afecta legibilidad para lectores
sin contexto previo de la API escaneada.

---

### [TD-007] Score display — espacio faltante entre número y barra ("100/ 100")

**File:** `pact/report/pdf_generator.py` — score `Table`, segunda columna  
**Recorded:** 2026-05-10

**Problem:**  
La score table usa `LEFTPADDING=0` y `RIGHTPADDING=0` en todas las celdas. El texto de la
segunda columna comienza con `/`, por lo que el resultado visual es `100/ 100` sin espacio
entre el número y la barra. El ojo del lector lo percibe como una fracción mal formateada.

**Root cause:**  
`LEFTPADDING=0` elimina el gap natural entre columnas. La segunda columna debería tener al
menos 4–6 pt de padding izquierdo para recrear el espacio visual.

**Proposed fix:**  
Añadir `("LEFTPADDING", (1, 0), (1, -1), 6)` en el TableStyle de la score table, o cambiar
el literal de `"/ 100"` a `" / 100"` (espacio no-separable `&nbsp;` si se usa Paragraph markup).

**Impact while unfixed:**  
Cosmético. Visible en cualquier score ≥ 10 (dos dígitos o más).

---

Próxima sesión: fix TD-007 (score spacing), investigar TD-010/011 (reglas PACT-001/002), scan adicional.
