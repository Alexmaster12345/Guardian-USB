"""Vulnerability/finding routes: list/filter, update remediation status."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from guardian.api.auth import require_api_key
from guardian.core.models import FindingStatus, Severity
from guardian.core.schemas import CVERead, FindingRead, FindingUpdate
from guardian.database.engine import session_scope
from guardian.database.repositories.vulnerability_repository import VulnerabilityRepository

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"],
                   dependencies=[Depends(require_api_key)])


@router.get("/findings", response_model=list[FindingRead])
def list_findings(
    asset_id: int | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    limit: int = 200,
    offset: int = 0,
):
    with session_scope() as session:
        findings = VulnerabilityRepository(session).list_findings(
            asset_id=asset_id, severity=severity, status=status, limit=limit, offset=offset
        )
        return [FindingRead.model_validate(f) for f in findings]


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(finding_id: int, payload: FindingUpdate):
    with session_scope() as session:
        repo = VulnerabilityRepository(session)
        finding = repo.get_finding(finding_id)
        if not finding:
            raise HTTPException(404, "Finding not found")
        repo.update_finding(finding, status=payload.status, assigned_to=payload.assigned_to)
        return FindingRead.model_validate(finding)


@router.get("/cves", response_model=list[CVERead])
def list_cves(limit: int = 100, offset: int = 0):
    with session_scope() as session:
        cves = VulnerabilityRepository(session).list_cves(limit=limit, offset=offset)
        return [CVERead.model_validate(c) for c in cves]


@router.get("/cves/{cve_id}", response_model=CVERead)
def get_cve(cve_id: str):
    with session_scope() as session:
        cve = VulnerabilityRepository(session).get_cve(cve_id)
        if not cve:
            raise HTTPException(404, "CVE not found")
        return CVERead.model_validate(cve)
