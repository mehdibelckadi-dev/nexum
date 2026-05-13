"""CLI-level tests for nexum scan --format."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from nexum.cli import app as nexum_app

_runner  = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


class TestScanSummaryFormat:
    def test_summary_format_contains_score(self):
        # sample_openapi.yaml → 3×CRITICAL(NEXUM-001) = 75 pts
        result = _runner.invoke(
            nexum_app,
            ["scan", str(FIXTURES / "sample_openapi.yaml"), "--format", "summary"],
        )
        assert result.exit_code == 0
        assert "75 / 100" in result.output

    def test_summary_format_contains_rule_breakdown(self):
        result = _runner.invoke(
            nexum_app,
            ["scan", str(FIXTURES / "sample_openapi.yaml"), "--format", "summary"],
        )
        assert result.exit_code == 0
        assert "NEXUM-001" in result.output  # first rule — 3 findings
        assert "NEXUM-005" in result.output  # last rule — 0 findings, always shown
