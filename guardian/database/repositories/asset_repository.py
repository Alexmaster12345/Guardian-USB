"""CRUD repository for assets and their software/services."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from guardian.core.models import Asset, Service, Software, utcnow


class AssetRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get(self, asset_id: int) -> Asset | None:
        return self.session.get(Asset, asset_id)

    def get_detail(self, asset_id: int) -> Asset | None:
        stmt = (
            select(Asset)
            .where(Asset.id == asset_id)
            .options(selectinload(Asset.software), selectinload(Asset.services))
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def get_by_ip(self, ip_address: str) -> Asset | None:
        stmt = select(Asset).where(Asset.ip_address == ip_address)
        return self.session.execute(stmt).scalar_one_or_none()

    def list(self, limit: int = 100, offset: int = 0) -> list[Asset]:
        stmt = select(Asset).limit(limit).offset(offset).order_by(Asset.id)
        return list(self.session.execute(stmt).scalars())

    def count(self) -> int:
        return self.session.query(Asset).count()

    def create(self, asset: Asset) -> Asset:
        self.session.add(asset)
        self.session.flush()
        return asset

    def upsert_by_ip(self, asset: Asset) -> Asset:
        """Insert or update an asset keyed on IP address."""
        existing = self.get_by_ip(asset.ip_address) if asset.ip_address else None
        if existing is None:
            return self.create(asset)
        for field in (
            "hostname", "mac_address", "os_name", "os_version", "cpu",
            "memory_gb", "disk_gb", "manufacturer", "serial_number", "asset_type",
        ):
            val = getattr(asset, field)
            if val is not None:
                setattr(existing, field, val)
        existing.last_seen = utcnow()
        self.session.flush()
        return existing

    def add_software(self, asset_id: int, sw: Software) -> Software:
        sw.asset_id = asset_id
        self.session.add(sw)
        self.session.flush()
        return sw

    def add_service(self, asset_id: int, svc: Service) -> Service:
        svc.asset_id = asset_id
        self.session.add(svc)
        self.session.flush()
        return svc

    def update(self, asset: Asset, **fields) -> Asset:
        for key, value in fields.items():
            if value is not None and hasattr(asset, key):
                setattr(asset, key, value)
        self.session.flush()
        return asset

    def delete(self, asset: Asset) -> None:
        self.session.delete(asset)
        self.session.flush()
