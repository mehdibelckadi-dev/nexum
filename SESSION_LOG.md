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

Próxima sesión: scan contra API real → Notion o MCP GitHub → luego Bloque 9 PDF.
