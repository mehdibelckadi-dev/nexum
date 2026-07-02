# Nexum

![CI](https://github.com/mehdibelckadi-dev/nexum/actions/workflows/ci.yml/badge.svg)
![PyPI](https://img.shields.io/pypi/v/nexum-scanner)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

The GitHub REST API exposes **404** endpoints an autonomous agent could misuse. Twilio's v2010 API: **62**. DigitalOcean's: **220** — including `DELETE /v2/droplets` with no resource identifier and `POST /v2/registries/subscription` with no idempotency guard. Nexum found every one of them with a deterministic scan, in under a second, without touching a live system.

That is the whole idea: read the spec, not the traffic.

## Why this exists

AI agents now call APIs on their own. They retry on network failures, chain tools together, and act without a human watching each request. But MCP and OpenAPI specs were written for human developers — people who read the docs, understand the blast radius of a call, and stop before doing something irreversible. An LLM agent has none of that context. It has the spec.

So the spec is where the risk lives. A `DELETE` with no required resource identifier is harmless when a careful engineer writes the request by hand and harmful the moment an agent issues it against an ambiguous scope. A mutation with no `Idempotency-Key` is fine until a retry after a dropped connection creates the charge twice. A credential passed in a query string is a latent leak that only matters when something logs the URL.

Nexum analyzes an MCP or OpenAPI definition statically and produces two artifacts: a **Trust Manifest** (JSON, machine-readable) and a **Risk Report** (PDF, human-readable). The risk engine is fully deterministic — five rules, reproducible scoring, and **no LLM in any risk decision**. Every finding carries the exact fragment of the spec that triggered it, so nothing is inferred and nothing is invented. When a value genuinely cannot be derived from the spec, the manifest says `REQUIRES_HUMAN_REVIEW` instead of guessing.

## How it works

Nexum normalizes the input spec (MCP tool definitions and OpenAPI are mapped to a common shape) and runs five rules over it. Each match produces a `Finding` with the offending path and method, the exact evidence snippet, a plain-English explanation, and a concrete guardrail suggestion.

| Rule | Name | What it detects | Severity |
|------|------|-----------------|----------|
| **NEXUM-001** | `AuthLeakageRisk` | Credentials passed in the query string | CRITICAL |
| **NEXUM-002** | `DestructiveAmbiguity` | Deletion with no specific resource identifier | CRITICAL |
| **NEXUM-003** | `UnboundedScope` | Wildcard params, or `DELETE`/`PATCH` with no required filter | HIGH |
| **NEXUM-004** | `IdempotencyMissing` | Mutations with no `Idempotency-Key` header | HIGH · CRITICAL on financial domains |
| **NEXUM-005** | `SchemaVolatility` | `additionalProperties: true` on mutation schemas | MEDIUM |

The **Risk Score** sums severity points — CRITICAL 25, HIGH 10, MEDIUM 5, LOW 1 — capped at 100. Crucially, at most **three instances of any single rule** contribute to the score. The first few occurrences establish that a problem is real and systemic; the fiftieth adds no new information and would only saturate the number. Without that cap, a 220-endpoint API with one repeated issue scores identically to a genuinely catastrophic one, and the score loses its power to discriminate. Scores map to **Tier 0** (0–30, low), **Tier 1** (31–60, moderate), and **Tier 2** (61–100, high).

NEXUM-004 additionally escalates from HIGH to CRITICAL when the endpoint is in a financial or otherwise irreversible domain (`charges`, `payments`, `refunds`, `transfers`, …). A duplicated comment is a trivial cleanup; a duplicated charge is a chargeback, a dispute, and a PCI-DSS problem. Same rule, different consequence — so the severity reflects it.

## Quick start

```bash
pip install nexum-scanner
nexum scan spec.yaml                         # Trust Manifest (JSON) + Risk Score
nexum scan spec.yaml --format summary        # human-readable terminal table
nexum report spec.yaml --output report.pdf   # 2-page PDF Risk Report
```

`nexum report` also takes `--triage` to append an optional, advisory LLM prioritization section — off by default; see [Architecture](#architecture).

## Example

Running the summary format against an OpenAPI fixture that ships with the repo:

```console
$ nexum scan nexum/tests/fixtures/sample_openapi.yaml --format summary
══════════════════════════════════════════
 NEXUM SCAN — sample_openapi.yaml
══════════════════════════════════════════
 Score     75 / 100
 Tier      2 — HIGH RISK
 Findings  3 total · 3 CRITICAL
──────────────────────────────────────────
 NEXUM-001  AuthLeakageRisk       3  CRITICAL
 NEXUM-002  DestructiveAmbiguity  0  —
 NEXUM-003  UnboundedScope        0  —
 NEXUM-004  IdempotencyMissing    0  —
 NEXUM-005  SchemaVolatility      0  —
══════════════════════════════════════════
```

The default output (no `--format`) is the Trust Manifest as JSON:

```json
{
  "manifest_version": "1.0-draft",
  "inferred_risk_tier": 2,
  "nexum_risk_score": 75,
  "model_compatibility_range": "REQUIRES_HUMAN_REVIEW",
  "findings_summary": [
    {
      "rule_id": "NEXUM-001",
      "rule_name": "AuthLeakageRisk",
      "severity": "CRITICAL",
      "path": "/invoices",
      "method": "GET",
      "confidence": "HIGH"
    }
  ]
}
```

## The registry

Nexum has scanned **2,608 public APIs** and published the results as an open registry of Trust Manifests and Risk Reports. Browse it at **[getnexum.dev](https://getnexum.dev)**.

## Architecture

Nexum is built as two strictly separated layers, and the separation is the point.

**Layer 1 — Deterministic core.** Ingestor, rules, scorer, manifest generator, validator. No LLM anywhere. The same spec always yields the same findings, the same score, and the same tier. This is the layer that decides risk, and it is fully auditable: every number traces back to a specific rule and an exact spec fragment. You can re-run it a thousand times and diff the output byte-for-byte.

**Layer 2 — LLM triage (opt-in).** An optional layer (`nexum/agent/triage.py`, enabled with `--triage`) that only *reprioritizes* findings and suggests remediation order. It runs on the already-computed manifest and is **fail-closed**: a strict allowlist rejects the entire LLM response if it contains a single unexpected field. The model can never read or alter severity, score, tier, or confidence — those aren't in its output schema, and anything extra it tries to return is discarded wholesale rather than filtered. If the call fails, times out, or returns malformed JSON, the report degrades gracefully to a generic "triage unavailable" notice and the deterministic output is untouched. The failure cause is categorized internally (operational vs. integrity) for logs only; it never reaches the user-facing report.

Why bother with the wall between the layers? Because the value of a risk score is that it is trustworthy and reproducible. The instant an LLM sits anywhere in the scoring path, the score becomes non-deterministic and un-auditable — and "the AI said it's a 60" is not something you can defend to a security team. Nexum keeps the model strictly additive: helpful for prioritization, powerless over the verdict.

The Trust Manifest format is specified separately at [nexum-trust-manifest](https://github.com/mehdibelckadi-dev/nexum-trust-manifest).

## Design decisions

A few choices worth calling out, because they were deliberate:

- **Deterministic rules over an LLM classifier.** An LLM could plausibly flag more subtle issues, but it would trade away reproducibility and auditability — the two properties that make a risk score usable. Every finding here can be explained by pointing at a rule and a line of the spec.
- **Fail-closed, allowlist, not denylist.** The triage parser accepts an explicit set of three fields and rejects anything else. A denylist ("strip out `severity` and `score`") fails open the day the model invents a new field nobody thought to block. An allowlist fails safe by construction.
- **A per-rule score cap.** Volume of findings measures API surface area, not concentration of risk. Capping each rule's contribution keeps the score discriminating between "one systemic problem across a huge API" and "several genuinely critical, distinct problems."
- **`REQUIRES_HUMAN_REVIEW` instead of a guess.** The manifest marks fields it cannot derive from the spec rather than fabricating a plausible-looking value. A wrong-but-confident field is worse than an honest gap.

## Limitations

Nexum performs **static analysis of a specification** — it does not test a running system, and its findings are potential design risks, not confirmed vulnerabilities. The rules are heuristics: they can produce false positives (e.g. a token in a path that is a domain identifier, not a credential) and false negatives (a destructively-named tool that the method normalization doesn't catch). Those are tracked as known technical debt, and the manifest's `confidence` field and `REQUIRES_HUMAN_REVIEW` markers exist precisely so a human stays in the loop. Nexum is a triage tool for narrowing where to look, not a rubber stamp.

## Development

```bash
git clone https://github.com/mehdibelckadi-dev/nexum.git
cd nexum
pip install -e .
pytest        # 193 tests
```

CI runs on every push to `main`: Nexum scans a sample spec with itself and fails the build if the risk tier exceeds a configured threshold — the tool is its own smoke test. Contributions are welcome. Two rules for a PR: every scanner rule ships with tests, and the deterministic core stays LLM-free (Layer 2 is the only place a model may live). Run `pytest` green before opening one.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
