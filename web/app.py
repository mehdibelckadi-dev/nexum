"""FastAPI web interface — wraps the Nexum scanner pipeline."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from nexum.core import engine
from nexum.core.ingestor import NexumIngestError, ingest
from nexum.core.scorer import calculate
from nexum.manifest.generator import generate
from nexum.report.pdf_generator import generate_pdf

app = FastAPI(title="Nexum Scanner", docs_url=None, redoc_url=None)

_TIER_LABEL = {0: "Tier 0 — LOW RISK", 1: "Tier 1 — MODERATE RISK", 2: "Tier 2 — HIGH RISK"}
_ALLOWED_SUFFIXES = {".json", ".yaml", ".yml"}
_STATIC = Path(__file__).parent / "static"


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


if __name__ == "__main__":
    uvicorn.run("web.app:app", host="127.0.0.1", port=8000, reload=True)
