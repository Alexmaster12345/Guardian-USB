"""Tests for CPE building and CVE matching."""
from guardian.core.models import CVE, Severity, Software
from guardian.fingerprinting.cpe_builder import build_cpe, build_cpe_from_software, cpe_matches
from guardian.vulnerability_engine.cve_matcher import CVEMatcher


def _cve(cve_id, cpe_matches_list, sev=Severity.HIGH):
    return CVE(cve_id=cve_id, description="test", cvss_score=7.5, severity=sev,
               cpe_matches=cpe_matches_list)


def test_build_cpe_normalizes():
    cpe = build_cpe("a", "Apache Software", "Log4j", "2.14.1")
    assert cpe.startswith("cpe:2.3:a:apache_software:log4j:2.14.1")


def test_build_cpe_from_software():
    sw = Software(vendor="apache", product="log4j", version="2.14.1")
    assert build_cpe_from_software(sw) == "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"


def test_cpe_matches_wildcard():
    target = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    pattern = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert cpe_matches(target, pattern)


def test_cpe_no_match_different_product():
    target = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    pattern = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert not cpe_matches(target, pattern)


def test_version_range_match():
    cve = _cve("CVE-2021-44228", [
        {"cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"}
    ])
    matcher = CVEMatcher([cve])
    matched = matcher.match_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "2.14.1")
    assert len(matched) == 1


def test_version_above_range_no_match():
    cve = _cve("CVE-2021-44228", [
        {"cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0"}
    ])
    matcher = CVEMatcher([cve])
    matched = matcher.match_cpe("cpe:2.3:a:apache:log4j:2.17.0:*:*:*:*:*:*:*", "2.17.0")
    assert matched == []


def test_plain_string_cpe_entry():
    cve = _cve("CVE-TEST", ["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"])
    matcher = CVEMatcher([cve])
    matched = matcher.match_cpe("cpe:2.3:o:microsoft:windows:10:*:*:*:*:*:*:*", "10")
    assert len(matched) == 1
