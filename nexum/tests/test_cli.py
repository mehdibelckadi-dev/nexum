"""CLI-level tests for nexum scan --format."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from nexum.cli import app as nexum_app

_runner  = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def _write_malformed_yaml(tmp_path: Path) -> Path:
    """A YAML file that is valid UTF-8 but contains a character YAML forbids.

    Mirrors the real-world SendGrid spec that triggered TD-014: the byte
    sequence decodes cleanly as UTF-8 (U+009F, a C1 control character) but
    yaml.safe_load() rejects it as an "unacceptable character".
    """
    spec = tmp_path / "malformed.yaml"
    spec.write_bytes(
        b'openapi: "3.0.0"\ninfo:\n  title: Broken\npaths:\n  /x:\n    get:\n'
        b'      summary: "bad \xc2\x9f char"\n'
    )
    return spec


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


class TestIngestErrorExitCode:
    """TD-014 regression: a malformed input must exit with a code distinct

    from any validator verdict (1 = DO_NOT_DISTRIBUTE, 2 = REVIEW_REQUIRED),
    so a parse failure can never be reported as a risk verdict downstream
    (see scripts/batch_scan.sh and .github/actions/nexum-scan/action.yml,
    both of which branch on exit code to classify the outcome).
    """

    def test_scan_malformed_yaml_exits_with_ingest_error_code(self, tmp_path):
        spec = _write_malformed_yaml(tmp_path)
        result = _runner.invoke(nexum_app, ["scan", str(spec)])
        assert result.exit_code == 3
        assert "Invalid YAML" in result.output

    def test_report_malformed_yaml_exits_with_ingest_error_code_not_do_not_distribute(
        self, tmp_path
    ):
        spec = _write_malformed_yaml(tmp_path)
        output_pdf = tmp_path / "report.pdf"
        result = _runner.invoke(
            nexum_app,
            ["report", str(spec), "--validate", "--output", str(output_pdf)],
        )
        assert result.exit_code == 3
        assert result.exit_code != 1  # must not be mistaken for DO_NOT_DISTRIBUTE
        assert "Invalid YAML" in result.output
        assert not output_pdf.exists()

    def test_validate_manifest_malformed_json_exits_with_ingest_error_code(self, tmp_path):
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text("{not valid json")
        result = _runner.invoke(nexum_app, ["validate-manifest", str(manifest_file)])
        assert result.exit_code == 3
        assert result.exit_code != 1  # must not be mistaken for DO_NOT_DISTRIBUTE
        assert "invalid JSON" in result.output
