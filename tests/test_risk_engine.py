"""Tests for the risk scoring engine."""
from guardian.core.models import Criticality
from guardian.risk_engine.prioritizer import prioritize_findings, top_n
from guardian.risk_engine.scorer import compute_risk_score


def test_low_risk_internal_asset():
    result = compute_risk_score(
        cvss_base=5.0, internet_facing=False, criticality=Criticality.LOW,
        exploit_available=False, actively_exploited=False,
    )
    # 5.0*0.4=2.0 + 0.5*1.5=0.75 + 0.5*1.5=0.75 = 3.5
    assert result.score == 3.5
    assert result.breakdown["cvss_component"] == 2.0
    assert result.breakdown["total"] == 3.5


def test_critical_internet_facing_actively_exploited_caps_at_10():
    result = compute_risk_score(
        cvss_base=10.0, internet_facing=True, criticality=Criticality.CRITICAL,
        exploit_available=True, actively_exploited=True,
    )
    # 4.0 + 3.0 + 3.0 + 1.5 + 2.0 = 13.5 -> capped 10.0
    assert result.score == 10.0


def test_breakdown_components():
    result = compute_risk_score(
        cvss_base=7.5, internet_facing=True, criticality=Criticality.HIGH,
        exploit_available=True, actively_exploited=False,
    )
    b = result.breakdown
    assert b["cvss_component"] == 3.0
    assert b["exposure_component"] == 3.0
    assert b["criticality_component"] == 2.25
    assert b["exploit_component"] == 1.5
    assert b["active_exploit_component"] == 0.0
    # 3.0+3.0+2.25+1.5 = 9.75 -> rounded to 1 decimal
    assert result.score == 9.8


def test_string_criticality_accepted():
    result = compute_risk_score(0.0, False, "Medium", False, False)
    # exposure 0.75 + criticality 1.5 = 2.25 -> rounded to 1 decimal
    assert result.score == 2.2


def test_prioritize_and_top_n():
    class F:
        def __init__(self, rs, sev):
            self.risk_score = rs
            self.severity = sev
            self.found_at = 0

    findings = [F(3.0, "Low"), F(9.0, "Critical"), F(6.0, "Medium")]
    ranked = prioritize_findings(findings)
    assert ranked[0].risk_score == 9.0
    assert ranked[-1].risk_score == 3.0
    assert len(top_n(findings, 2)) == 2
