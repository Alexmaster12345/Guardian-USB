"""Final risk scoring engine.

risk_score = min(10.0,
    cvss_base * 0.4 +
    (2.0 if internet_facing else 0.5) * 1.5 +
    criticality_weight * 1.5 +
    (1.5 if exploit_available else 0.0) +
    (2.0 if actively_exploited else 0.0)
)
"""
from __future__ import annotations

from dataclasses import dataclass

from guardian.core.models import Criticality

CRITICALITY_WEIGHTS: dict[str, float] = {
    "Critical": 2.0,
    "High": 1.5,
    "Medium": 1.0,
    "Low": 0.5,
}


def _criticality_weight(criticality) -> float:
    if isinstance(criticality, Criticality):
        criticality = criticality.value
    return CRITICALITY_WEIGHTS.get(str(criticality), 1.0)


@dataclass
class RiskResult:
    score: float
    breakdown: dict[str, float]


def compute_risk_score(
    cvss_base: float,
    internet_facing: bool,
    criticality,
    exploit_available: bool,
    actively_exploited: bool,
) -> RiskResult:
    """Compute the composite risk score and return score + breakdown."""
    cvss_base = float(cvss_base or 0.0)
    cvss_component = cvss_base * 0.4
    exposure_component = (2.0 if internet_facing else 0.5) * 1.5
    criticality_component = _criticality_weight(criticality) * 1.5
    exploit_component = 1.5 if exploit_available else 0.0
    active_component = 2.0 if actively_exploited else 0.0

    total = (
        cvss_component
        + exposure_component
        + criticality_component
        + exploit_component
        + active_component
    )
    score = round(min(10.0, total), 1)

    breakdown = {
        "cvss_component": round(cvss_component, 3),
        "exposure_component": round(exposure_component, 3),
        "criticality_component": round(criticality_component, 3),
        "exploit_component": round(exploit_component, 3),
        "active_exploit_component": round(active_component, 3),
        "total": score,
    }
    return RiskResult(score=score, breakdown=breakdown)


class RiskScorer:
    """Convenience wrapper that scores findings from asset + CVE data."""

    def score_cve(self, cve, asset) -> RiskResult:
        return compute_risk_score(
            cvss_base=getattr(cve, "cvss_score", 0.0) or 0.0,
            internet_facing=getattr(asset, "is_internet_facing", False),
            criticality=getattr(asset, "criticality", Criticality.MEDIUM),
            exploit_available=getattr(cve, "exploit_available", False),
            actively_exploited=getattr(cve, "actively_exploited", False),
        )

    def score_finding(
        self,
        cvss_base: float,
        asset,
        exploit_available: bool = False,
        actively_exploited: bool = False,
    ) -> RiskResult:
        return compute_risk_score(
            cvss_base=cvss_base,
            internet_facing=getattr(asset, "is_internet_facing", False),
            criticality=getattr(asset, "criticality", Criticality.MEDIUM),
            exploit_available=exploit_available,
            actively_exploited=actively_exploited,
        )
