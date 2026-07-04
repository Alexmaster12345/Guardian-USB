"""Scheduled task definitions: scan, report, alert, update."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from guardian.core.config import get_settings
from guardian.core.models import FindingStatus, Scan, ScanStatus, ScanType, Severity
from guardian.database.engine import session_scope
from guardian.database.repositories.asset_repository import AssetRepository
from guardian.database.repositories.scan_repository import ScanRepository
from guardian.database.repositories.vulnerability_repository import VulnerabilityRepository

logger = logging.getLogger("guardian.tasks")


def scan_task(target_range: str | None = None, scan_type: str = "Full") -> dict:
    """Run a discovery + vulnerability scan over the given range."""
    from guardian.discovery import AssetCollector, NetworkScanner, ServiceDiscovery
    from guardian.vulnerability_engine import VulnerabilityEngine

    with session_scope() as session:
        scan_repo = ScanRepository(session)
        asset_repo = AssetRepository(session)
        vuln_repo = VulnerabilityRepository(session)

        scan = scan_repo.create(Scan(
            name=f"scheduled-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}",
            scan_type=ScanType(scan_type),
            target_range=target_range,
        ))
        scan_repo.mark_running(scan)

        cves = vuln_repo.all_cves()
        engine = VulnerabilityEngine(cves)
        scanner = NetworkScanner()
        collector = AssetCollector()
        svc_disc = ServiceDiscovery()

        findings_total = 0
        assets_total = 0
        try:
            hosts = scanner.scan(target_range) if target_range else []
            for host in hosts:
                asset = asset_repo.upsert_by_ip(collector.from_discovered_host(host))
                assets_total += 1
                services = svc_disc.services_for_host(host, asset.is_internet_facing)
                for svc in services:
                    asset_repo.add_service(asset.id, svc)
                findings = engine.analyze(asset, software=list(asset.software),
                                          services=services, scan_id=scan.id)
                for f in findings:
                    vuln_repo.add_finding(f)
                findings_total += len(findings)
            scan_repo.mark_completed(scan, findings_total, assets_total)
        except Exception as exc:
            logger.exception("Scan task failed: %s", exc)
            scan_repo.mark_failed(scan)
            raise

        return {"scan_id": scan.id, "assets": assets_total, "findings": findings_total}


def report_task(fmt: str = "html") -> str:
    """Generate a report to the configured report directory."""
    from guardian.reporting import ReportGenerator

    settings = get_settings()
    ext = {"html": "html", "json": "json", "csv": "csv"}.get(fmt, "html")
    out = settings.report_dir / f"report-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}.{ext}"
    ReportGenerator().generate(fmt=fmt, output_path=out)
    logger.info("Report generated: %s", out)
    return str(out)


def alert_task(min_severity: str = "High") -> list[dict]:
    """Return new findings at or above the given severity (alerting hook)."""
    order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    threshold = order.get(Severity(min_severity), 3)
    alerts: list[dict] = []
    with session_scope() as session:
        vuln_repo = VulnerabilityRepository(session)
        findings = vuln_repo.list_findings(status=FindingStatus.NEW, limit=500)
        for f in findings:
            if order.get(f.severity, 0) >= threshold:
                alerts.append({
                    "finding_id": f.id, "title": f.title,
                    "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
                    "risk_score": f.risk_score,
                })
    logger.info("Alert task: %d findings >= %s", len(alerts), min_severity)
    return alerts


def update_task() -> int:
    """Sync the CVE database from NVD (online)."""
    from guardian.updates import NVDSync

    count = NVDSync().sync(max_records=200)
    logger.info("Update task: %d CVEs synced", count)
    return count
