# nexum-scan action

Scans your MCP or OpenAPI spec for agentic security risks.

## Prerequisites

The calling workflow must check out the Nexum repository before using this
action, as the install step runs `pip install -e .` from the working directory:

```yaml
- uses: actions/checkout@v4
- uses: ./.github/actions/nexum-scan
  with:
    spec-file: openapi.yaml
```

## Usage

```yaml
- uses: mehdibelckadi-dev/nexum/.github/actions/nexum-scan@main
  with:
    spec-file: openapi.yaml
    fail-on-tier: '2'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `spec-file` | Path to OpenAPI or MCP spec file | Yes | — |
| `fail-on-tier` | Fail if risk tier >= this value (0–2) | No | `2` |
| `validate` | Run validator after scan (`true`/`false`) | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `risk-tier` | Risk tier (0=low, 1=moderate, 2=high) |
| `risk-score` | Aggregate risk score 0–100 |
| `findings-count` | Total findings |

## Validate behaviour

When `validate: true`, the action runs `nexum validate` against the manifest
and blocks **only** on `DO_NOT_DISTRIBUTE` (exit code 1). A `REVIEW_REQUIRED`
result (exit code 2) is logged but does not fail the step.
