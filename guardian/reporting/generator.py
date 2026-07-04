"""Orchestrates report data assembly and export."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from guardian.core.models import Severity
from guardian.database.engine import session_scope
from guardian.database.repositories.asset_repository import AssetRepository
from guardian.database.repositories.scan_repository import ScanRepository
from guardian.database.repositories.vulnerability_repository import VulnerabilityRepository
from guardian.reporting.exporters import CSVExporter, HTMLExporter, JSONExporter
from guardian.risk_engine.prioritizer import top_n


def _sev_value(sev) -> str:
    return sev.value if isinstance(sev, Severity) else str(sev)


class ReportGenerator:
    """Builds a report data dict from the DB and exports it."""

    def build_report_data(self, scope: str | None = None) -> dict:
        with session_scope() as session:
            asset_repo = AssetRepository(session)
            vuln_repo = VulnerabilityRepository(session)
            scan_repo = ScanRepository(session)

            assets = asset_repo.list(limit=1000)
            findings = vuln_repo.list_findings(limit=2000)
            compliance = scan_repo.list_compliance()

            severity_counts = vuln_repo.severity_counts()

            asset_dicts = [self._asset_dict(a) for a in assets]
            asset_names = {a.id: (a.hostname or a.ip_address or f"asset-{a.id}") for a in assets}

            finding_dicts = [self._finding_dict(f, asset_names) for f in findings]
            top = [self._finding_dict(f, asset_names) for f in top_n(findings, 10)]

            overall = round(
                sum(f.risk_score or 0 for f in findings) / len(findings), 1
            ) if findings else 0.0

            comp_dicts = [self._compliance_dict(c) for c in compliance]
            passed = sum(1 for c in compliance if c.passed)
            comp_summary = {
                "total": len(compliance),
                "passed": passed,
                "failed": len(compliance) - passed,
                "pass_rate": round(passed / len(compliance) * 100, 1) if compliance else 0.0,
            } if compliance else None

        return {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "scope": scope,
            "summary": {
                "asset_count": len(assets),
                "finding_count": len(findings),
                "overall_risk_score": overall,
            },
            "severity_counts": severity_counts,
            "assets": asset_dicts,
            "findings": finding_dicts,
            "top_findings": top,
            "compliance": comp_dicts,
            "compliance_summary": comp_summary,
            "trend": None,
        }

    def generate(self, fmt: str = "html", output_path: str | Path | None = None, scope: str | None = None) -> str:
        data = self.build_report_data(scope)
        fmt = fmt.lower()
        if fmt == "html":
            return HTMLExporter().export(data, output_path)
        if fmt == "json":
            return JSONExporter().export(data, output_path)
        if fmt == "csv":
            return CSVExporter().export(data, output_path)
        raise ValueError(f"Unsupported report format: {fmt}")

    @staticmethod
    def _asset_dict(a) -> dict:
        return {
            "id": a.id, "hostname": a.hostname, "ip_address": a.ip_address,
            "os_name": a.os_name, "os_version": a.os_version, "asset_type": a.asset_type,
            "criticality": _sev_value(a.criticality), "is_internet_facing": a.is_internet_facing,
        }

    @staticmethod
    def _finding_dict(f, asset_names: dict) -> dict:
        return {
            "id": f.id, "asset_id": f.asset_id, "asset": asset_names.get(f.asset_id, f.asset_id),
            "title": f.title, "severity": _sev_value(f.severity), "risk_score": f.risk_score,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "finding_type": f.finding_type.value if hasattr(f.finding_type, "value") else f.finding_type,
            "found_at": f.found_at.isoformat() if f.found_at else None,
        }

    @staticmethod
    def _compliance_dict(c) -> dict:
        return {
            "framework": c.framework, "rule_id": c.rule_id, "rule_name": c.rule_name,
            "passed": c.passed, "details": c.details,
        }
