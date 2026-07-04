"""Pydantic v2 schemas mirroring the ORM models for the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from guardian.core.models import (
    Criticality,
    FindingStatus,
    FindingType,
    ScanStatus,
    ScanType,
    Severity,
)


class ORMBase(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


# ---- Software ----
class SoftwareBase(BaseModel):
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    patch_level: str | None = None
    architecture: str | None = None
    is_eol: bool = False


class SoftwareCreate(SoftwareBase):
    pass


class SoftwareRead(ORMBase, SoftwareBase):
    id: int
    asset_id: int
    install_date: datetime | None = None
    eol_date: datetime | None = None


# ---- Service ----
class ServiceBase(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    banner: str | None = None
    encryption: str | None = None
    auth_method: str | None = None
    is_exposed: bool = False


class ServiceCreate(ServiceBase):
    pass


class ServiceRead(ORMBase, ServiceBase):
    id: int
    asset_id: int


# ---- Asset ----
class AssetBase(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    cpu: str | None = None
    memory_gb: float | None = None
    disk_gb: float | None = None
    manufacturer: str | None = None
    serial_number: str | None = None
    asset_type: str | None = "PC"
    owner: str | None = None
    location: str | None = None
    criticality: Criticality = Criticality.MEDIUM
    is_internet_facing: bool = False


class AssetCreate(AssetBase):
    software: list[SoftwareCreate] = Field(default_factory=list)
    services: list[ServiceCreate] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    owner: str | None = None
    location: str | None = None
    criticality: Criticality | None = None
    is_internet_facing: bool | None = None
    asset_type: str | None = None


class AssetRead(ORMBase, AssetBase):
    id: int
    created_at: datetime
    last_seen: datetime


class AssetDetail(AssetRead):
    software: list[SoftwareRead] = Field(default_factory=list)
    services: list[ServiceRead] = Field(default_factory=list)


# ---- CVE ----
class CVEBase(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: Severity = Severity.MEDIUM
    cpe_matches: list = Field(default_factory=list)
    exploit_available: bool = False
    actively_exploited: bool = False
    patch_available: bool = False
    references: list = Field(default_factory=list)


class CVERead(ORMBase, CVEBase):
    id: int
    published_date: datetime | None = None
    modified_date: datetime | None = None


# ---- Finding ----
class FindingBase(BaseModel):
    title: str
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    risk_score: float = 0.0
    finding_type: FindingType = FindingType.CVE


class FindingRead(ORMBase, FindingBase):
    id: int
    asset_id: int
    cve_id: int | None = None
    scan_id: int | None = None
    status: FindingStatus
    assigned_to: str | None = None
    found_at: datetime
    resolved_at: datetime | None = None
    verified_at: datetime | None = None


class FindingUpdate(BaseModel):
    status: FindingStatus | None = None
    assigned_to: str | None = None


# ---- Scan ----
class ScanCreate(BaseModel):
    name: str
    scan_type: ScanType = ScanType.FULL
    target_range: str | None = None


class ScanRead(ORMBase):
    id: int
    name: str
    scan_type: ScanType
    status: ScanStatus
    target_range: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    findings_count: int = 0
    assets_discovered: int = 0


# ---- Compliance ----
class ComplianceResultRead(ORMBase):
    id: int
    asset_id: int
    scan_id: int | None = None
    framework: str
    rule_id: str
    rule_name: str
    passed: bool
    details: str | None = None
    checked_at: datetime


# ---- Scheduled Job ----
class ScheduledJobCreate(BaseModel):
    name: str
    job_type: str
    cron_expression: str
    target: str | None = None
    enabled: bool = True


class ScheduledJobRead(ORMBase, ScheduledJobCreate):
    id: int
    last_run: datetime | None = None
    next_run: datetime | None = None


class RiskBreakdown(BaseModel):
    cvss_component: float
    exposure_component: float
    criticality_component: float
    exploit_component: float
    active_exploit_component: float
    total: float
