"""Asset routes: list, get, create, update, trigger discovery."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from guardian.api.auth import require_api_key
from guardian.core.models import Asset, Service, Software
from guardian.core.schemas import AssetCreate, AssetDetail, AssetRead, AssetUpdate
from guardian.database.engine import session_scope
from guardian.database.repositories.asset_repository import AssetRepository

router = APIRouter(prefix="/assets", tags=["assets"], dependencies=[Depends(require_api_key)])


@router.get("", response_model=list[AssetRead])
def list_assets(limit: int = 100, offset: int = 0):
    with session_scope() as session:
        assets = AssetRepository(session).list(limit=limit, offset=offset)
        return [AssetRead.model_validate(a) for a in assets]


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: int):
    with session_scope() as session:
        asset = AssetRepository(session).get_detail(asset_id)
        if not asset:
            raise HTTPException(404, "Asset not found")
        return AssetDetail.model_validate(asset)


@router.post("", response_model=AssetDetail, status_code=201)
def create_asset(payload: AssetCreate):
    with session_scope() as session:
        repo = AssetRepository(session)
        data = payload.model_dump(exclude={"software", "services"})
        asset = repo.create(Asset(**data))
        for sw in payload.software:
            repo.add_software(asset.id, Software(**sw.model_dump()))
        for svc in payload.services:
            repo.add_service(asset.id, Service(**svc.model_dump()))
        session.flush()
        detail = repo.get_detail(asset.id)
        return AssetDetail.model_validate(detail)


@router.patch("/{asset_id}", response_model=AssetRead)
def update_asset(asset_id: int, payload: AssetUpdate):
    with session_scope() as session:
        repo = AssetRepository(session)
        asset = repo.get(asset_id)
        if not asset:
            raise HTTPException(404, "Asset not found")
        repo.update(asset, **payload.model_dump(exclude_unset=True))
        return AssetRead.model_validate(asset)


@router.post("/discover", response_model=dict)
def trigger_discovery(target_range: str):
    """Trigger a synchronous discovery scan over a target range."""
    from guardian.automation.tasks import scan_task

    result = scan_task(target_range=target_range, scan_type="Discovery")
    return result
