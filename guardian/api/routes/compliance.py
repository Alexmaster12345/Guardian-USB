"""Compliance routes: run checks and fetch results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from guardian.api.auth import require_api_key
from guardian.compliance.checker import ComplianceChecker
from guardian.core.schemas import ComplianceResultRead
from guardian.database.engine import session_scope
from guardian.database.repositories.asset_repository import AssetRepository
from guardian.database.repositories.scan_repository import ScanRepository

router = APIRouter(prefix="/compliance", tags=["compliance"], dependencies=[Depends(require_api_key)])


@router.get("/results", response_model=list[ComplianceResultRead])
def list_results(asset_id: int | None = None):
    with session_scope() as session:
        results = ScanRepository(session).list_compliance(asset_id=asset_id)
        return [ComplianceResultRead.model_validate(r) for r in results]


@router.post("/run/{asset_id}", response_model=dict)
def run_compliance(asset_id: int):
    with session_scope() as session:
        asset_repo = AssetRepository(session)
        scan_repo = ScanRepository(session)
        asset = asset_repo.get_detail(asset_id)
        if not asset:
            raise HTTPException(404, "Asset not found")

        checker = ComplianceChecker()
        outcomes = checker.run(asset)
        for result in checker.to_results(asset, outcomes):
            scan_repo.add_compliance_result(result)
        return {"asset_id": asset_id, **checker.summary(outcomes)}
