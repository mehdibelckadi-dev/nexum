"""FastAPI web interface — wraps the Nexum scanner pipeline."""

from __future__ import annotations

import html as _html
import io
import re
import tempfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from nexum.core import engine
from nexum.core.ingestor import NexumIngestError, ingest
from nexum.core.scorer import calculate
from nexum.manifest.generator import generate
from nexum.report.pdf_generator import generate_pdf
from web.email_utils import EmailDeliveryError, send_report_email
from web.scan_log import log_scan_event

app = FastAPI(title="Nexum Scanner", docs_url=None, redoc_url=None)
_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

# CSS and JS are shared across every page with no version/hash in the URL, so a
# stale browser cache after a deploy silently breaks layout or behavior (seen
# firsthand: Chrome served a cached nexum.css with no network round-trip at
# all, since StaticFiles sets no Cache-Control by default and heuristic caching
# kicked in). Force revalidation on every load — ETag/Last-Modified from
# StaticFiles are untouched, so a 304 still short-circuits the actual transfer.
# Images carry no correctness risk if briefly stale, so they keep default
# caching for the bandwidth savings.
_NO_CACHE_STATIC_PREFIXES = ("/static/css/", "/static/js/")


@app.middleware("http")
async def _no_cache_for_css_js(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith(_NO_CACHE_STATIC_PREFIXES):
        response.headers["Cache-Control"] = "no-cache"
    return response

_TIER_LABEL = {0: "Tier 0 — LOW RISK", 1: "Tier 1 — MODERATE RISK", 2: "Tier 2 — HIGH RISK"}
_BADGE_CONFIGS = {
    0: {"color": "#4c1",    "text": "Nexum Certified · Tier 0 · Safe"},
    1: {"color": "#db1",    "text": "Nexum Certified · Tier 1 · Moderate Risk"},
    2: {"color": "#e05d44", "text": "Nexum Certified · Tier 2 · High Risk"},
}
_SVG_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="74" height="20" viewBox="0 0 520 140">'
    '<linearGradient id="s" x2="0" y2="100%">'
    '<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
    '<stop offset="1" stop-opacity=".1"/>'
    '</linearGradient>'
    '<clipPath id="r"><rect width="520" height="140" rx="21" fill="#fff"/></clipPath>'
    '<g clip-path="url(#r)">'
    '<rect width="520" height="140" fill="{color}"/>'
    '<rect width="520" height="140" fill="url(#s)"/>'
    '</g>'
    '<g fill="#fff" text-anchor="middle"'
    ' font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="110">'
    '<text x="260" y="108" fill="#010101" fill-opacity=".3">{text}</text>'
    '<text x="260" y="98">{text}</text>'
    '</g>'
    '</svg>'
)
_ALLOWED_SUFFIXES = {".json", ".yaml", ".yml"}
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _pipeline(content: bytes, filename: str):
    suffix = Path(filename).suffix.lower()
    if suffix not in _ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{suffix}'. Use .json, .yaml, or .yml.")
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as tmp:
        tmp.write(content)
        tmp.flush()
        try:
            spec = ingest(tmp.name)
        except NexumIngestError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
    findings = engine.run(spec)
    result = calculate(findings)
    manifest = generate(findings, result, filename, spec)
    return findings, result, manifest


@app.get("/")
async def index():
    return FileResponse(_STATIC / "index.html")


@app.get("/favicon.ico")
async def favicon():
    # Browsers (and Google's favicon service for history/bookmarks) probe this
    # well-known root path directly, regardless of <link rel="icon"> in the HTML.
    return FileResponse(_STATIC / "img" / "favicon.ico", media_type="image/x-icon")


@app.get("/registry")
async def registry():
    return FileResponse(_STATIC / "registry.html")


@app.get("/blog")
async def blog():
    return FileResponse(_STATIC / "blog" / "index.html")


@app.get("/blog/2517-apis-scanned")
async def blog_article():
    return FileResponse(_STATIC / "blog" / "2517-apis-scanned.html")


@app.get("/blog/ai-act-aplazamiento-2026")
async def blog_article_ai_act():
    return FileResponse(_STATIC / "blog" / "ai-act-aplazamiento-2026.html")


@app.get("/blog/nexum-004-fabian-williams")
async def blog_article_fabian_williams():
    return FileResponse(_STATIC / "blog" / "nexum-004-fabian-williams.html")


@app.get("/registry-data")
async def registry_data():
    path = _STATIC / "registry_data.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail="Registry data not available.")
    return JSONResponse(content=__import__("json").loads(path.read_text(encoding="utf-8")))


@app.get("/reports/{filename}")
async def serve_report(filename: str):
    report_path = _STATIC / "reports" / filename
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(report_path, media_type="application/pdf")


@app.post("/scan")
async def scan(request: Request, file: UploadFile = File(...)):
    content = await file.read()
    filename = file.filename or "upload"
    findings, result, _ = _pipeline(content, filename)
    log_scan_event(
        endpoint="scan",
        filename=filename,
        content=content,
        client_ip=request.client.host if request.client else None,
        findings_count=len(findings),
        score=result.score,
        tier=result.tier,
    )
    return JSONResponse({
        "score": result.score,
        "tier": result.tier,
        "tier_label": _TIER_LABEL[result.tier],
        "findings_count": len(findings),
        "top_findings": [
            {"rule_id": f.rule_id, "severity": f.severity, "path": f.path, "method": f.method}
            for f in findings[:5]
        ],
    })


@app.post("/report")
async def report(request: Request, file: UploadFile = File(...), email: str | None = Form(None)):
    content = await file.read()
    filename = file.filename or "upload"
    findings, result, manifest = _pipeline(content, filename)
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp_pdf:
        generate_pdf(findings, result, manifest, filename, Path(tmp_pdf.name))
        pdf_bytes = Path(tmp_pdf.name).read_bytes()
    stem = Path(filename).stem
    pdf_filename = f"{stem}_nexum.pdf"

    # Email delivery is strictly optional and additive: any failure here
    # (bad address, SMTP outage, missing config) must never prevent the PDF
    # from downloading normally, which is why this is try/except rather than
    # raising an HTTPException.
    email_address = (email or "").strip()
    email_requested = bool(email_address)
    email_status = None
    if email_requested:
        if _EMAIL_PATTERN.match(email_address):
            try:
                send_report_email(email_address, pdf_bytes, pdf_filename)
                email_status = "sent"
            except EmailDeliveryError as exc:
                print(f"[nexum] report email failed: {exc}")
                email_status = "failed"
        else:
            email_status = "failed"

    log_scan_event(
        endpoint="report",
        filename=filename,
        content=content,
        client_ip=request.client.host if request.client else None,
        findings_count=len(findings),
        score=result.score,
        tier=result.tier,
        email_requested=email_requested,
    )

    headers = {"Content-Disposition": f'attachment; filename="{pdf_filename}"'}
    if email_status:
        headers["X-Nexum-Email-Status"] = email_status
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers=headers)


@app.get("/badge/{tier}")
async def badge(tier: int):
    if tier not in _BADGE_CONFIGS:
        raise HTTPException(status_code=404, detail=f"Unknown tier '{tier}'. Valid tiers: 0, 1, 2.")
    cfg = _BADGE_CONFIGS[tier]
    svg = _SVG_TEMPLATE.format(color=cfg["color"], text=_html.escape(cfg["text"]))
    return Response(
        content=svg,
        media_type="image/svg+xml",
        headers={"Cache-Control": "max-age=3600"},
    )


@app.get("/badge/{tier}/markdown")
async def badge_markdown(tier: int):
    if tier not in _BADGE_CONFIGS:
        raise HTTPException(status_code=404, detail=f"Unknown tier '{tier}'. Valid tiers: 0, 1, 2.")
    return Response(
        content=f"![Nexum Certified](https://getnexum.dev/badge/{tier})\n",
        media_type="text/plain",
    )


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
