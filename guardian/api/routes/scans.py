"""Scan routes: start scan, status, history."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from guardian.api.auth import require_api_key
from guardian.core.models import Scan
from guardian.core.schemas import ScanCreate, ScanRead
from guardian.database.engine import session_scope
from guardian.database.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(require_api_key)])


@router.get("", response_model=list[ScanRead])
def list_scans(limit: int = 50, offset: int = 0):
    with session_scope() as session:
        scans = ScanRepository(session).list(limit=limit, offset=offset)
        return [ScanRead.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int):
    with session_scope() as session:
        scan = ScanRepository(session).get(scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        return ScanRead.model_validate(scan)


@router.post("", response_model=ScanRead, status_code=201)
def start_scan(payload: ScanCreate):
    """Start a scan. If a target_range is provided a synchronous scan runs."""
    from guardian.automation.tasks import scan_task

    if payload.target_range:
        result = scan_task(target_range=payload.target_range, scan_type=payload.scan_type.value)
        with session_scope() as session:
            scan = ScanRepository(session).get(result["scan_id"])
            return ScanRead.model_validate(scan)

    with session_scope() as session:
        scan = ScanRepository(session).create(Scan(
            name=payload.name, scan_type=payload.scan_type, target_range=payload.target_range,
        ))
        return ScanRead.model_validate(scan)
