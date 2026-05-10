# PACT — Briefing de Sesión para Claude Code

## Language rule
All code, comments, variable names, function names, docstrings, error messages,
and file content must be written in English. Only respond to me in Spanish.

## Misión de este sprint
Construir el Pact Scanner: una herramienta CLI que analiza definiciones MCP u OpenAPI
y devuelve un Trust Manifest draft (JSON) + Reporte de Riesgo (PDF).

## Filosofía — leer antes de escribir una sola línea
- El engine de reglas es 100% determinista. CERO LLM en ninguna función.
- Cada regla devuelve un Finding con evidence_snippet (el fragmento exacto del spec).
- El Trust Manifest marca REQUIRES_HUMAN_REVIEW en lugar de inventar valores.
- No pasar al siguiente bloque sin pytest en verde en el bloque anterior.

## Stack
- Python 3.11+
- pydantic v2, pyyaml, typer, reportlab, pytest

## Estructura del proyecto
pact/
├── core/
│   ├── ingestor.py
│   ├── engine.py
│   ├── scorer.py
│   └── rules/
│       ├── base.py
│       ├── auth_leakage.py       # PACT-001
│       ├── destructive_ambiguity.py  # PACT-002
│       ├── unbounded_scope.py    # PACT-003
│       ├── idempotency.py        # PACT-004
│       └── schema_volatility.py  # PACT-005
├── manifest/
│   └── generator.py
├── report/
│   └── pdf_generator.py
├── cli.py
├── tests/
│   ├── fixtures/
│   │   ├── sample_mcp.json
│   │   └── sample_openapi.yaml
│   └── test_rules.py
└── data/
    └── findings_log.jsonl

## Orden de construcción — no saltarse pasos
1. core/ingestor.py
2. core/rules/base.py + dataclass Finding
3. Las 5 reglas (una por archivo)
4. core/engine.py
5. CHECKPOINT pytest
6. core/scorer.py
7. manifest/generator.py
8. cli.py → comando: pact scan <archivo>
9. report/pdf_generator.py (último)

## Las 5 reglas

| ID       | Clase                | Qué detecta                                        | Severidad |
|----------|----------------------|----------------------------------------------------|-----------|
| PACT-001 | AuthLeakageRisk      | Credenciales en query_string                       | CRITICAL  |
| PACT-002 | DestructiveAmbiguity | Borrado sin ID específico                          | CRITICAL  |
| PACT-003 | UnboundedScope       | Wildcard params o DELETE/PATCH sin filtros         | HIGH      |
| PACT-004 | IdempotencyMissing   | Mutaciones sin Idempotency-Key                     | HIGH      |
| PACT-005 | SchemaVolatility     | additionalProperties: true en schemas de mutación  | MEDIUM    |

## Formato Finding (dataclass)
rule_id: str          # "PACT-001"
rule_name: str        # "AuthLeakageRisk"
severity: str         # CRITICAL | HIGH | MEDIUM | LOW
path: str             # "/endpoint/afectado"
method: str           # GET | POST | DELETE | PATCH...
evidence_snippet: str # fragmento exacto del JSON/YAML que dispara la regla
human_explanation: str
guardrail_suggestion: str

## Risk Score
CRITICAL=25, HIGH=10, MEDIUM=5, LOW=1
Score = min(100, suma de puntos)
Tier 0: 0-30 | Tier 1: 31-60 | Tier 2: 61-100

## Trust Manifest draft — estructura
{
  "manifest_version": "1.0-draft",
  "scanned_at": "<ISO timestamp>",
  "source_file": "<nombre archivo>",
  "inferred_risk_tier": 0,
  "pact_risk_score": 0,
  "model_compatibility_range": ">=gpt-4o-2024-01",
  "auto_detected_invariants": {
    "immutable_fields": [],
    "numeric_limits": {},
    "required_headers": []
  },
  "findings_summary": [],
  "manual_review_required": []
}

## PDF — estructura (2 páginas máximo)
Página 1: Pact Risk Score (número grande), Risk Tier, Top 3 findings con evidence
Página 2: Tabla completa de findings + guardrail_suggestions

## Lo que NO hacer en esta sesión
- No construir Sidecar, Proxy ni SDK
- No conectar a servicios externos ni APIs
- No integrar LLM en ninguna función
- No generar el PDF antes de que el engine pase pytest
