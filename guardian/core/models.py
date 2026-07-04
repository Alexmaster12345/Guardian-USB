"""SQLAlchemy ORM models for all Guardian USB entities."""
from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for all models."""


class Criticality(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Severity(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class FindingStatus(str, enum.Enum):
    NEW = "New"
    CONFIRMED = "Confirmed"
    ASSIGNED = "Assigned"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    VERIFIED = "Verified"
    EXCEPTION_ACCEPTED = "ExceptionAccepted"


class FindingType(str, enum.Enum):
    CVE = "CVE"
    CONFIG = "Config"
    COMPLIANCE = "Compliance"
    SERVICE = "Service"


class ScanType(str, enum.Enum):
    DISCOVERY = "Discovery"
    VULNERABILITY = "Vulnerability"
    COMPLIANCE = "Compliance"
    FULL = "Full"


class ScanStatus(str, enum.Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17))
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    cpu: Mapped[str | None] = mapped_column(String(255))
    memory_gb: Mapped[float | None] = mapped_column(Float)
    disk_gb: Mapped[float | None] = mapped_column(Float)
    manufacturer: Mapped[str | None] = mapped_column(String(128))
    serial_number: Mapped[str | None] = mapped_column(String(128))
    asset_type: Mapped[str | None] = mapped_column(String(64), default="PC")
    owner: Mapped[str | None] = mapped_column(String(128))
    location: Mapped[str | None] = mapped_column(String(128))
    criticality: Mapped[Criticality] = mapped_column(SAEnum(Criticality), default=Criticality.MEDIUM)
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    software: Mapped[list["Software"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    services: Mapped[list["Service"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Software(Base):
    __tablename__ = "software"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    vendor: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    install_date: Mapped[datetime | None] = mapped_column(DateTime)
    patch_level: Mapped[str | None] = mapped_column(String(64))
    architecture: Mapped[str | None] = mapped_column(String(32))
    is_eol: Mapped[bool] = mapped_column(Boolean, default=False)
    eol_date: Mapped[datetime | None] = mapped_column(DateTime)

    asset: Mapped["Asset"] = relationship(back_populates="software")


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[str | None] = mapped_column(String(128))
    banner: Mapped[str | None] = mapped_column(Text)
    encryption: Mapped[str | None] = mapped_column(String(64))
    auth_method: Mapped[str | None] = mapped_column(String(64))
    is_exposed: Mapped[bool] = mapped_column(Boolean, default=False)

    asset: Mapped["Asset"] = relationship(back_populates="services")


class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.MEDIUM)
    published_date: Mapped[datetime | None] = mapped_column(DateTime)
    modified_date: Mapped[datetime | None] = mapped_column(DateTime)
    cpe_matches: Mapped[list] = mapped_column(JSON, default=list)
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    actively_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    references: Mapped[list] = mapped_column(JSON, default=list)

    findings: Mapped[list["Finding"]] = relationship(back_populates="cve")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    cve_id: Mapped[int | None] = mapped_column(ForeignKey("cves.id"), nullable=True, index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SAEnum(Severity), default=Severity.MEDIUM)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[FindingStatus] = mapped_column(SAEnum(FindingStatus), default=FindingStatus.NEW)
    assigned_to: Mapped[str | None] = mapped_column(String(128))
    found_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    finding_type: Mapped[FindingType] = mapped_column(SAEnum(FindingType), default=FindingType.CVE)

    asset: Mapped["Asset"] = relationship(back_populates="findings")
    cve: Mapped["CVE | None"] = relationship(back_populates="findings")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    scan_type: Mapped[ScanType] = mapped_column(SAEnum(ScanType), default=ScanType.FULL)
    status: Mapped[ScanStatus] = mapped_column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    target_range: Mapped[str | None] = mapped_column(String(255))
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    framework: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(64))
    rule_name: Mapped[str] = mapped_column(String(255))
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    job_type: Mapped[str] = mapped_column(String(64))
    cron_expression: Mapped[str] = mapped_column(String(128))
    target: Mapped[str | None] = mapped_column(String(255))
    last_run: Mapped[datetime | None] = mapped_column(DateTime)
    next_run: Mapped[datetime | None] = mapped_column(DateTime)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
