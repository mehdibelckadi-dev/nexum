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

## Risk Score
CRITICAL=25, HIGH=10, MEDIUM=5, LOW=1
Score = min(100, suma de puntos)
Tier 0: 0-30 | Tier 1: 31-60 | Tier 2: 61-100

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

## Lo que NO hacer
- No construir Sidecar, Proxy ni SDK
- No conectar a servicios externos
- No integrar LLM en ninguna función
- No cambiar IDs de reglas a PACT-XXX (el nombre correcto es NEXUM-XXX)
