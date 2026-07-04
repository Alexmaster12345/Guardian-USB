"""FastAPI application factory."""
from __future__ import annotations

from fastapi import FastAPI

from guardian.core.config import get_settings
from guardian.database.engine import init_db


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Guardian USB Vulnerability Management Platform",
        version="0.1.0",
        description="REST API for asset discovery, vulnerability scanning, "
                    "compliance, and reporting.",
    )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()

    @app.get("/health", tags=["system"])
    def health() -> dict:
        return {"status": "ok", "service": "guardian-usb", "version": "0.1.0"}

    # Register routers.
    from guardian.api.routes import assets, compliance, reports, scans, vulnerabilities

    app.include_router(assets.router)
    app.include_router(scans.router)
    app.include_router(vulnerabilities.router)
    app.include_router(compliance.router)
    app.include_router(reports.router)

    return app


app = create_app()
