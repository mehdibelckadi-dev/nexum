# NEXUM — Briefing de Sesión para Claude Code

## Misión de este sprint
Construir el Nexum Scanner: una herramienta CLI que analiza definiciones MCP u OpenAPI
y devuelve un Trust Manifest draft (JSON) + Reporte de Riesgo (PDF).

## Filosofía — leer antes de escribir una sola línea
- El engine de reglas es 100% determinista. CERO LLM en ninguna función.
- Cada regla devuelve un Finding con evidence_snippet (el fragmento exacto del spec).
- El Trust Manifest marca REQUIRES_HUMAN_REVIEW en lugar de inventar valores.
- No pasar al siguiente bloque sin pytest en verde en el bloque anterior.

## Language rule
All code, comments, variable names, function names, docstrings, error messages,
and file content must be written in English. Only respond to me in Spanish.

## Stack
- Python 3.11+
- pydantic v2, pyyaml, typer, reportlab, pytest

## Estructura del proyecto
nexum/
├── core/
│   ├── ingestor.py
│   ├── engine.py
│   ├── scorer.py
│   └── rules/
│       ├── base.py
│       ├── auth_leakage.py           # NEXUM-001
│       ├── destructive_ambiguity.py  # NEXUM-002
│       ├── unbounded_scope.py        # NEXUM-003
│       ├── idempotency.py            # NEXUM-004
│       └── schema_volatility.py      # NEXUM-005
├── manifest/
│   └── generator.py
├── report/
│   └── pdf_generator.py
├── cli.py                            # nexum scan <archivo>
├── tests/
│   ├── fixtures/
│   │   ├── sample_mcp.json
│   │   └── sample_openapi.yaml
│   └── test_rules.py
└── data/
    └── findings_log.jsonl

## Estado actual (Sprint 0 completado)
- 92/92 tests en verde
- CLI funcional: nexum scan <archivo>
- PDF: nexum report <archivo> --output report.pdf
- Scans reales: GitHub REST API (404 findings), Twilio v2010 (62 findings)
- findings_log.jsonl: 72 entradas

## Las 5 reglas

| ID        | Clase                | Qué detecta                                        | Severidad |
|-----------|----------------------|----------------------------------------------------|-----------|
| NEXUM-001 | AuthLeakageRisk      | Credenciales en query_string                       | CRITICAL  |
| NEXUM-002 | DestructiveAmbiguity | Borrado sin ID específico                          | CRITICAL  |
| NEXUM-003 | UnboundedScope       | Wildcard params o DELETE/PATCH sin filtros         | HIGH      |
| NEXUM-004 | IdempotencyMissing   | Mutaciones sin Idempotency-Key                     | HIGH      |
| NEXUM-005 | SchemaVolatility     | additionalProperties: true en schemas de mutación  | MEDIUM    |

## Formato Finding
rule_id: str           # "NEXUM-001"
rule_name: str         # "AuthLeakageRisk"
severity: str          # CRITICAL | HIGH | MEDIUM | LOW
path: str              # "/endpoint/afectado"
method: str            # GET | POST | DELETE | PATCH...
evidence_snippet: str  # fragmento exacto del JSON/YAML
human_explanation: str
guardrail_suggestion: str


## Risk Score — Two Distinct Concepts

**Scanner Risk Score (static — implemented today):**
Score = min(100, Σ points per severity)
CRITICAL=25, HIGH=10, MEDIUM=5, LOW=1
Tier 0: 0-30 | Tier 1: 31-60 | Tier 2: 61-100
This is what the scanner produces. This is what appears in the PDF.

**Runtime Block Score (Layer 1 — not yet implemented):**
Score = (Impact × Scope) - Reversibility
Determines whether the SDK blocks a call at runtime.
Sprint 2+. Does not exist in any current output.

Never mix these two in the same explanation or in the same code path.

## Trust Manifest draft
{
  "manifest_version": "1.0-draft",
  "scanned_at": "<ISO timestamp>",
  "source_file": "<nombre archivo>",
  "inferred_risk_tier": 0,
  "nexum_risk_score": 0,
  "model_compatibility_range": "REQUIRES_HUMAN_REVIEW",
  "auto_detected_invariants": {
    "immutable_fields": [],
    "numeric_limits": {},
    "required_headers": []
  },
  "findings_summary": [],
  "manual_review_required": []
}

## PDF — estructura (2 páginas máximo)
Página 1: Nexum Risk Score (número grande), Risk Tier, tabla breakdown por regla, Top 3 findings
Página 2: Tabla completa de findings + guardrail_suggestions + "...and N more" si volumen alto

## Deuda técnica activa
TD-001: Heurístico frágil en NEXUM-004 — tools como remove_record o purge_data
no se detectan. Solución futura: x-nexum-intent annotation en Trust Manifest v1.1.

TD-005: MCP annotations (readOnlyHint, idempotentHint, destructiveHint) are discarded
by _normalize_mcp in ingestor.py. Rules cannot consult them, producing false positives
in NEXUM-004 (e.g. write_file and create_directory fire despite idempotentHint:true,
directory_tree fires despite readOnlyHint:true). Fix: propagate annotations as x-mcp-*
extensions on the operation object during normalization so rules can filter by them.

## Lo que NO hacer
- No construir Sidecar, Proxy ni SDK
- No conectar a servicios externos
- No integrar LLM en ninguna función
- No cambiar IDs de reglas a PACT-XXX (el nombre correcto es NEXUM-XXX)
- No mezclar Scanner Risk Score con Runtime Block Score en el mismo output
- No implementar candidatos NEXUM-00X que requieran NLP o LLM para detección

## Deuda Técnica Activa

**TD-001** — Heurístico frágil en NEXUM-004 (existente)

**TD-005** — RESUELTO. MCP annotations propagadas al normalizador.

**TD-006** — write_query gap (existente)

**TD-007 — git_branch falso positivo estructural:**
Tool: git_branch en mcp-server-git Python
Causa: token "branch" ambiguo entre list (lectura) y create (escritura)
No resoluble con heurístico sin romper git_create_branch
Fix correcto: readOnlyHint:true en servidor Python, o known_false_positives 
en Trust Manifest
Sprint 2: Opción C — campo known_false_positives en manifest generator

**TD-008 — git_reset human_explanation corregida (RESUELTO):**
Premisa original incorrecta: el tool NO expone --hard.
repo.index.reset() = git reset HEAD --mixed. Working directory intacto.
Riesgo real: pérdida de toda la staging area acumulada por git_add calls
previos, sin posibilidad de detectar ejecución duplicada via Idempotency-Key.
No es candidato a NEXUM-002 — método HTTP normalizado es POST, no DELETE.
Fix aplicado: dict _OPERATION_EXPLANATIONS en idempotency.py con texto
específico para git_reset. Sin cambio de lógica de detección.
TD-009 registrado: mover _OPERATION_EXPLANATIONS a archivo externo
si supera 5 entradas.
