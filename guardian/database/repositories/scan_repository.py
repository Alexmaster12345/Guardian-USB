"""CRUD repository for scans and compliance results."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian.core.models import ComplianceResult, Scan, ScanStatus, utcnow


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, scan: Scan) -> Scan:
        self.session.add(scan)
        self.session.flush()
        return scan

    def get(self, scan_id: int) -> Scan | None:
        return self.session.get(Scan, scan_id)

    def list(self, limit: int = 100, offset: int = 0) -> list[Scan]:
        stmt = select(Scan).order_by(Scan.id.desc()).limit(limit).offset(offset)
        return list(self.session.execute(stmt).scalars())

    def mark_running(self, scan: Scan) -> Scan:
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        self.session.flush()
        return scan

    def mark_completed(self, scan: Scan, findings_count: int = 0, assets_discovered: int = 0) -> Scan:
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = utcnow()
        scan.findings_count = findings_count
        scan.assets_discovered = assets_discovered
        self.session.flush()
        return scan

    def mark_failed(self, scan: Scan) -> Scan:
        scan.status = ScanStatus.FAILED
        scan.completed_at = utcnow()
        self.session.flush()
        return scan

    def add_compliance_result(self, result: ComplianceResult) -> ComplianceResult:
        self.session.add(result)
        self.session.flush()
        return result

    def list_compliance(self, asset_id: int | None = None) -> list[ComplianceResult]:
        stmt = select(ComplianceResult)
        if asset_id is not None:
            stmt = stmt.where(ComplianceResult.asset_id == asset_id)
        stmt = stmt.order_by(ComplianceResult.checked_at.desc())
        return list(self.session.execute(stmt).scalars())
