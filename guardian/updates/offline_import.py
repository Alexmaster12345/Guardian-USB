"""Import vulnerability data from local JSON files (air-gapped environments)."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from guardian.core.exceptions import VulnerabilityDBError
from guardian.core.models import CVE, Severity
from guardian.database.engine import session_scope
from guardian.database.repositories.vulnerability_repository import VulnerabilityRepository


def _parse_dt(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(str(value).split("Z")[0], fmt)
        except ValueError:
            continue
    return None


class OfflineImporter:
    """Loads CVEs from a Guardian-native JSON file or an NVD 2.0 feed dump."""

    def load_file(self, path: str | Path) -> list[dict]:
        p = Path(path)
        if not p.exists():
            raise VulnerabilityDBError(f"File not found: {p}")
        try:
            with p.open() as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            raise VulnerabilityDBError(f"Invalid JSON in {p}: {exc}") from exc

        if isinstance(data, dict) and "vulnerabilities" in data:
            return data["vulnerabilities"]
        if isinstance(data, dict) and "cves" in data:
            return data["cves"]
        if isinstance(data, list):
            return data
        raise VulnerabilityDBError("Unrecognized JSON structure for CVE import")

    def to_cve(self, record: dict) -> CVE | None:
        # NVD 2.0 nested structure
        if "cve" in record and isinstance(record["cve"], dict):
            from guardian.updates.nvd_sync import NVDSync
            return NVDSync().parse_cve(record)

        cve_id = record.get("cve_id") or record.get("id")
        if not cve_id:
            return None

        score = record.get("cvss_score")
        severity = record.get("severity")
        try:
            sev = Severity(severity) if severity else self._sev_from_score(score)
        except ValueError:
            sev = self._sev_from_score(score)

        return CVE(
            cve_id=cve_id,
            description=record.get("description"),
            cvss_score=score,
            cvss_vector=record.get("cvss_vector"),
            severity=sev,
            published_date=_parse_dt(record.get("published_date")),
            modified_date=_parse_dt(record.get("modified_date")),
            cpe_matches=record.get("cpe_matches", []) or [],
            references=record.get("references", []) or [],
            exploit_available=bool(record.get("exploit_available", False)),
            actively_exploited=bool(record.get("actively_exploited", False)),
            patch_available=bool(record.get("patch_available", False)),
        )

    @staticmethod
    def _sev_from_score(score) -> Severity:
        if score is None:
            return Severity.MEDIUM
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW

    def import_file(self, path: str | Path) -> int:
        records = self.load_file(path)
        stored = 0
        with session_scope() as session:
            repo = VulnerabilityRepository(session)
            for record in records:
                cve = self.to_cve(record)
                if cve:
                    repo.upsert_cve(cve)
                    stored += 1
        return stored
