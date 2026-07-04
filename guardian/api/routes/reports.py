"""Report routes: generate and download reports."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse

from guardian.api.auth import require_api_key
from guardian.reporting import ReportGenerator

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[Depends(require_api_key)])


@router.get("/generate")
def generate_report(format: str = "html", scope: str | None = None):
    fmt = format.lower()
    content = ReportGenerator().generate(fmt=fmt, scope=scope)
    if fmt == "html":
        return HTMLResponse(content=content)
    if fmt == "json":
        return PlainTextResponse(content=content, media_type="application/json")
    return PlainTextResponse(content=content, media_type="text/csv")


@router.get("/data")
def report_data(scope: str | None = None):
    return ReportGenerator().build_report_data(scope)
