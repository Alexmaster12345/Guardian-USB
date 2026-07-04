"""Sort and rank findings by risk score."""
from __future__ import annotations

from guardian.core.models import Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def _severity_rank(sev) -> int:
    if isinstance(sev, str):
        try:
            sev = Severity(sev)
        except ValueError:
            return 0
    return _SEVERITY_ORDER.get(sev, 0)


def prioritize_findings(findings: list) -> list:
    """Return findings sorted by risk_score desc, then severity, then recency."""
    return sorted(
        findings,
        key=lambda f: (
            getattr(f, "risk_score", 0.0) or 0.0,
            _severity_rank(getattr(f, "severity", None)),
            getattr(f, "found_at", None) or 0,
        ),
        reverse=True,
    )


def top_n(findings: list, n: int = 10) -> list:
    return prioritize_findings(findings)[:n]
