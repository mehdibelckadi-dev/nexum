"""FastAPI web interface — wraps the Nexum scanner pipeline."""

from __future__ import annotations

import html as _html
import io
import tempfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from nexum.core import engine
from nexum.core.ingestor import NexumIngestError, ingest
from nexum.core.scorer import calculate
from nexum.manifest.generator import generate
from nexum.report.pdf_generator import generate_pdf

app = FastAPI(title="Nexum Scanner", docs_url=None, redoc_url=None)
_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

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


@app.get("/registry")
async def registry():
    return FileResponse(_STATIC / "registry.html")


@app.get("/registry-data")
async def registry_data():
    path = _STATIC / "registry_data.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail="Registry data not available.")
    return JSONResponse(content=__import__("json").loads(path.read_text(encoding="utf-8")))


@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    content = await file.read()
    findings, result, _ = _pipeline(content, file.filename or "upload")
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
async def report(file: UploadFile = File(...)):
    content = await file.read()
    findings, result, manifest = _pipeline(content, file.filename or "upload")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=True) as tmp_pdf:
        generate_pdf(findings, result, manifest, file.filename or "upload", Path(tmp_pdf.name))
        pdf_bytes = Path(tmp_pdf.name).read_bytes()
    stem = Path(file.filename or "report").stem
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}_nexum.pdf"'},
    )


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
