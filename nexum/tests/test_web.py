"""HTTP endpoint tests for the Nexum web interface."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from web.app import app

client = TestClient(app)
FIXTURES = Path(__file__).parent / "fixtures"


def _upload(route: str, fixture: str):
    path = FIXTURES / fixture
    with open(path, "rb") as f:
        return client.post(route, files={"file": (fixture, f, "application/octet-stream")})


class TestScanEndpoint:
    def test_returns_200_for_valid_json(self):
        res = _upload("/scan", "real_github.json")
        assert res.status_code == 200

    def test_response_shape(self):
        data = _upload("/scan", "sample_mcp.json").json()
        for key in ("score", "tier", "tier_label", "findings_count", "top_findings"):
            assert key in data

    def test_score_is_int_in_range(self):
        data = _upload("/scan", "sample_mcp.json").json()
        assert isinstance(data["score"], int)
        assert 0 <= data["score"] <= 100

    def test_tier_is_0_1_or_2(self):
        data = _upload("/scan", "sample_mcp.json").json()
        assert data["tier"] in (0, 1, 2)

    def test_top_findings_capped_at_5(self):
        data = _upload("/scan", "real_github.json").json()
        assert len(data["top_findings"]) <= 5

    def test_top_findings_fields(self):
        data = _upload("/scan", "real_github.json").json()
        for f in data["top_findings"]:
            for key in ("rule_id", "severity", "path", "method"):
                assert key in f

    def test_valid_yaml(self):
        res = _upload("/scan", "sample_openapi.yaml")
        assert res.status_code == 200

    def test_invalid_file_type_returns_400(self):
        res = client.post("/scan", files={"file": ("spec.txt", b"hello", "text/plain")})
        assert res.status_code == 400


class TestReportEndpoint:
    def test_returns_pdf_content_type(self):
        res = _upload("/report", "sample_mcp.json")
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/pdf"

    def test_pdf_has_content(self):
        res = _upload("/report", "sample_mcp.json")
        assert len(res.content) > 1024

    def test_pdf_magic_bytes(self):
        res = _upload("/report", "sample_mcp.json")
        assert res.content[:4] == b"%PDF"

    def test_content_disposition_header(self):
        res = _upload("/report", "sample_mcp.json")
        assert "attachment" in res.headers.get("content-disposition", "")


class TestIndexEndpoint:
    def test_serves_html(self):
        res = client.get("/")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]


class TestRegistryDataEndpoint:
    def test_returns_200(self):
        res = client.get("/registry-data")
        assert res.status_code == 200

    def test_returns_json_content_type(self):
        res = client.get("/registry-data")
        assert "application/json" in res.headers["content-type"]

    def test_response_is_list(self):
        data = client.get("/registry-data").json()
        assert isinstance(data, list)

    def test_each_entry_has_required_fields(self):
        data = client.get("/registry-data").json()
        for entry in data:
            assert "api" in entry
            # new format fields (verdict field removed in v2 data)
            has_new = "total_findings" in entry
            has_legacy = "verdict" in entry
            assert has_new or has_legacy, f"Entry {entry.get('api')} has neither new nor legacy fields"

    def test_count_meets_minimum(self):
        data = client.get("/registry-data").json()
        assert len(data) >= 2500

    def test_new_format_fields_are_valid(self):
        data = client.get("/registry-data").json()
        new_format = [e for e in data if "total_findings" in e]
        for entry in new_format:
            assert isinstance(entry["total_findings"], int)
            assert entry["total_findings"] >= -1
            assert entry["tier"] in {0, 1, 2}
            assert isinstance(entry["critical"], int) and entry["critical"] >= 0
            assert isinstance(entry["score"], (int, float)) and 0 <= entry["score"] <= 100


class TestReportsStaticEndpoint:
    def test_report_404_for_missing_file(self):
        res = client.get("/reports/nonexistent.pdf")
        assert res.status_code == 404


class TestRegistryPageEndpoint:
    def test_registry_serves_html(self):
        res = client.get("/registry")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]


class TestBadgeEndpoint:
    def test_badge_tier0_returns_svg(self):
        res = client.get("/badge/0")
        assert res.status_code == 200
        assert res.headers["content-type"] == "image/svg+xml"
        assert "<svg" in res.text
        assert "Tier 0" in res.text
        assert "#4c1" in res.text

    def test_badge_tier2_returns_red_svg(self):
        res = client.get("/badge/2")
        assert res.status_code == 200
        assert "#e05d44" in res.text
        assert "Tier 2" in res.text

    def test_invalid_tier_returns_404(self):
        res = client.get("/badge/99")
        assert res.status_code == 404


class TestBlogEndpoints:
    def test_blog_index_returns_200(self):
        res = client.get("/blog")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]

    def test_blog_article_returns_200(self):
        res = client.get("/blog/2517-apis-scanned")
        assert res.status_code == 200
        assert "text/html" in res.headers["content-type"]
