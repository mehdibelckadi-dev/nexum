"""HTTP endpoint tests for the Nexum web interface."""

import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import web.email_utils as email_utils
from web.app import app


class _FakeResendResponse:
    """Stand-in for the httpx.Response returned by a Resend API call."""

    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakePost:
    """Stand-in for httpx.post — records every call, returns a canned
    response or raises a canned network-level exception."""

    def __init__(self, response: "_FakeResendResponse | None" = None, exception: Exception | None = None):
        self.response = response
        self.exception = exception
        self.calls: list[dict] = []

    def __call__(self, url, *, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        if self.exception is not None:
            raise self.exception
        return self.response

client = TestClient(app)
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_scan_log(tmp_path, monkeypatch):
    """Point NEXUM_SCAN_LOG_PATH at a throwaway file so tests never write
    into the real (gitignored) findings_log.jsonl used by the CLI/deploy."""
    monkeypatch.setenv("NEXUM_SCAN_LOG_PATH", str(tmp_path / "test_findings_log.jsonl"))


def _upload(route: str, fixture: str, data: dict | None = None):
    path = FIXTURES / fixture
    with open(path, "rb") as f:
        return client.post(route, files={"file": (fixture, f, "application/octet-stream")}, data=data or {})


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


class TestReportEmailOptIn:
    """Covers both branches of the optional email-delivery feature: the
    default (ignored) path must behave exactly like before, and every
    failure mode must still return the PDF (fail-open, never blocks)."""

    @pytest.fixture(autouse=True)
    def resend_env(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-resend-key")

    def test_no_email_field_leaves_flow_unchanged(self):
        res = _upload("/report", "sample_mcp.json")
        assert res.status_code == 200
        assert "x-nexum-email-status" not in res.headers
        assert res.content[:4] == b"%PDF"

    def test_valid_email_sends_and_reports_sent(self, monkeypatch):
        fake_post = _FakePost(response=_FakeResendResponse(200))
        monkeypatch.setattr(email_utils.httpx, "post", fake_post)

        res = _upload("/report", "sample_mcp.json", data={"email": "reviewer@example.com"})

        assert res.status_code == 200
        assert res.headers["x-nexum-email-status"] == "sent"
        assert res.content[:4] == b"%PDF"
        assert len(fake_post.calls) == 1
        call = fake_post.calls[0]
        assert call["url"] == "https://api.resend.com/emails"
        assert call["headers"]["Authorization"] == "Bearer test-resend-key"
        assert call["json"]["from"] == "Nexum <hello@getnexum.dev>"
        assert call["json"]["to"] == ["reviewer@example.com"]
        assert call["json"]["attachments"][0]["filename"].endswith("_nexum.pdf")

    def test_api_error_still_returns_pdf(self, monkeypatch):
        fake_post = _FakePost(response=_FakeResendResponse(422, text="invalid recipient"))
        monkeypatch.setattr(email_utils.httpx, "post", fake_post)

        res = _upload("/report", "sample_mcp.json", data={"email": "reviewer@example.com"})

        assert res.status_code == 200
        assert res.headers["x-nexum-email-status"] == "failed"
        assert res.content[:4] == b"%PDF"

    def test_network_failure_still_returns_pdf(self, monkeypatch):
        fake_post = _FakePost(exception=httpx.TimeoutException("timed out"))
        monkeypatch.setattr(email_utils.httpx, "post", fake_post)

        res = _upload("/report", "sample_mcp.json", data={"email": "reviewer@example.com"})

        assert res.status_code == 200
        assert res.headers["x-nexum-email-status"] == "failed"
        assert res.content[:4] == b"%PDF"

    def test_malformed_email_reports_failed_without_sending(self, monkeypatch):
        fake_post = _FakePost(response=_FakeResendResponse(200))
        monkeypatch.setattr(email_utils.httpx, "post", fake_post)

        res = _upload("/report", "sample_mcp.json", data={"email": "not-an-email"})

        assert res.status_code == 200
        assert res.headers["x-nexum-email-status"] == "failed"
        assert res.content[:4] == b"%PDF"
        assert len(fake_post.calls) == 0

    def test_missing_resend_api_key_reports_failed(self, monkeypatch):
        monkeypatch.delenv("RESEND_API_KEY", raising=False)

        res = _upload("/report", "sample_mcp.json", data={"email": "reviewer@example.com"})

        assert res.status_code == 200
        assert res.headers["x-nexum-email-status"] == "failed"
        assert res.content[:4] == b"%PDF"


class TestScanLogging:
    """The internal telemetry log must capture every /scan and /report call
    without ever requesting anything from the user."""

    def test_scan_appends_one_jsonl_record(self, tmp_path, monkeypatch):
        log_path = tmp_path / "scan_log.jsonl"
        monkeypatch.setenv("NEXUM_SCAN_LOG_PATH", str(log_path))

        res = _upload("/scan", "sample_mcp.json")
        assert res.status_code == 200

        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        for key in ("scan_id", "timestamp", "endpoint", "filename", "spec_sha256", "client_ip", "findings_count", "score", "tier"):
            assert key in record
        assert record["endpoint"] == "scan"
        assert record["email_requested"] is False

    def test_report_logs_email_requested_flag(self, tmp_path, monkeypatch):
        log_path = tmp_path / "scan_log.jsonl"
        monkeypatch.setenv("NEXUM_SCAN_LOG_PATH", str(log_path))
        monkeypatch.setenv("RESEND_API_KEY", "test-resend-key")
        monkeypatch.setattr(email_utils.httpx, "post", _FakePost(response=_FakeResendResponse(200)))

        res = _upload("/report", "sample_mcp.json", data={"email": "reviewer@example.com"})
        assert res.status_code == 200

        record = json.loads(log_path.read_text(encoding="utf-8").strip().splitlines()[0])
        assert record["endpoint"] == "report"
        assert record["email_requested"] is True

    def test_log_write_failure_does_not_break_scan(self, tmp_path, monkeypatch):
        # Point at a path whose parent can never be created (a file, not a
        # directory) so log_scan_event hits its OSError branch.
        blocked_parent = tmp_path / "not_a_directory"
        blocked_parent.write_text("blocking file")
        monkeypatch.setenv("NEXUM_SCAN_LOG_PATH", str(blocked_parent / "scan_log.jsonl"))

        res = _upload("/scan", "sample_mcp.json")
        assert res.status_code == 200


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
