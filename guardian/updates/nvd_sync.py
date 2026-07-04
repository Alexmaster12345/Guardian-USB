"""Fetch NVD 2.0 JSON feeds, parse CVEs, and upsert into the DB."""
from __future__ import annotations

from datetime import datetime

import requests

from guardian.core.config import get_settings
from guardian.core.exceptions import VulnerabilityDBError
from guardian.core.models import CVE, Severity
from guardian.database.engine import session_scope
from guardian.database.repositories.vulnerability_repository import VulnerabilityRepository


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M"):
        try:
            return datetime.strptime(value.split("Z")[0].replace("+00:00", ""), fmt)
        except ValueError:
            continue
    return None


def _severity_from_score(score: float | None, label: str | None) -> Severity:
    if label:
        try:
            return Severity(label.capitalize())
        except ValueError:
            pass
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


class NVDSync:
    """Synchronizes CVE data from the NVD 2.0 REST API."""

    def __init__(self, api_key: str | None = None, base_url: str | None = None) -> None:
        settings = get_settings()
        self.api_key = api_key or settings.nvd_api_key
        self.base_url = base_url or settings.nvd_base_url

    def _headers(self) -> dict:
        headers = {"User-Agent": "Guardian-USB/0.1"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def fetch_page(
        self,
        start_index: int = 0,
        results_per_page: int = 200,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
    ) -> dict:
        params = {"startIndex": start_index, "resultsPerPage": results_per_page}
        if pub_start_date:
            params["pubStartDate"] = pub_start_date
        if pub_end_date:
            params["pubEndDate"] = pub_end_date
        try:
            resp = requests.get(self.base_url, params=params, headers=self._headers(), timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            raise VulnerabilityDBError(f"NVD fetch failed: {exc}") from exc

    def parse_cve(self, item: dict) -> CVE | None:
        cve_data = item.get("cve", item)
        cve_id = cve_data.get("id")
        if not cve_id:
            return None

        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"),
            descriptions[0].get("value") if descriptions else None,
        )

        score, vector, label = self._extract_cvss(cve_data.get("metrics", {}))
        cpe_matches = self._extract_cpes(cve_data.get("configurations", []))
        refs = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]

        return CVE(
            cve_id=cve_id,
            description=description,
            cvss_score=score,
            cvss_vector=vector,
            severity=_severity_from_score(score, label),
            published_date=_parse_dt(cve_data.get("published")),
            modified_date=_parse_dt(cve_data.get("lastModified")),
            cpe_matches=cpe_matches,
            references=refs,
            exploit_available=False,
            actively_exploited=False,
            patch_available=bool(refs),
        )

    @staticmethod
    def _extract_cvss(metrics: dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                score = data.get("baseScore")
                vector = data.get("vectorString")
                label = data.get("baseSeverity") or entries[0].get("baseSeverity")
                return score, vector, label
        return None, None, None

    @staticmethod
    def _extract_cpes(configurations) -> list[dict]:
        result: list[dict] = []
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", True):
                        continue
                    entry = {"cpe": match.get("criteria")}
                    for k in ("versionStartIncluding", "versionEndExcluding", "versionEndIncluding"):
                        if match.get(k):
                            entry[k] = match[k]
                    result.append(entry)
        return result

    def sync(
        self,
        max_records: int = 2000,
        results_per_page: int = 200,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
    ) -> int:
        """Fetch and upsert CVEs. Returns number of CVEs stored."""
        stored = 0
        start_index = 0
        while start_index < max_records:
            page = self.fetch_page(
                start_index=start_index,
                results_per_page=results_per_page,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
            )
            vulns = page.get("vulnerabilities", [])
            if not vulns:
                break
            with session_scope() as session:
                repo = VulnerabilityRepository(session)
                for item in vulns:
                    cve = self.parse_cve(item)
                    if cve:
                        repo.upsert_cve(cve)
                        stored += 1
            total = page.get("totalResults", 0)
            start_index += results_per_page
            if start_index >= total:
                break
        return stored
