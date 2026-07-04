"""Tests for the compliance checker and rules."""
from guardian.compliance.checker import ComplianceChecker
from guardian.core.models import Asset, Criticality, Service


def _asset_with_services(services):
    a = Asset(hostname="host1", ip_address="10.0.0.5", criticality=Criticality.HIGH)
    a.services = services
    a.software = []
    return a


def test_ssh_hardening_pass():
    checker = ComplianceChecker()
    asset = _asset_with_services([])
    outcomes = checker.run(asset, extra={
        "sshd_config": {"PermitRootLogin": "no", "PasswordAuthentication": "no", "Protocol": "2"},
    })
    ssh = {o.rule_id: o for o in outcomes if o.rule_id.startswith("SSH")}
    assert ssh["SSH-01"].passed
    assert ssh["SSH-02"].passed
    assert ssh["SSH-03"].passed


def test_ssh_hardening_fail_root_login():
    checker = ComplianceChecker()
    outcomes = checker.run(_asset_with_services([]), extra={
        "sshd_config": {"PermitRootLogin": "yes", "PasswordAuthentication": "yes"},
    })
    ssh = {o.rule_id: o for o in outcomes}
    assert not ssh["SSH-01"].passed
    assert not ssh["SSH-02"].passed


def test_password_policy_rules():
    checker = ComplianceChecker()
    outcomes = checker.run(_asset_with_services([]), extra={
        "password_policy": {"min_length": 14, "require_complexity": True,
                            "max_age_days": 60, "lockout_threshold": 5, "history": 10},
    })
    pwd = {o.rule_id: o for o in outcomes if o.rule_id.startswith("PWD")}
    assert all(o.passed for o in pwd.values())


def test_firewall_sensitive_port_exposed_fails():
    svc = Service(port=3389, protocol="tcp", service_name="rdp", is_exposed=True)
    checker = ComplianceChecker()
    outcomes = checker.run(_asset_with_services([svc]), extra={
        "firewall": {"enabled": True, "default_policy": "deny"},
    })
    fw = {o.rule_id: o for o in outcomes if o.rule_id.startswith("FW")}
    assert fw["FW-01"].passed
    assert fw["FW-02"].passed
    assert not fw["FW-03"].passed


def test_disk_encryption_rules():
    checker = ComplianceChecker()
    outcomes = checker.run(_asset_with_services([]), extra={
        "encryption": {"disk_encrypted": True, "method": "LUKS", "swap_encrypted": True},
    })
    enc = {o.rule_id: o for o in outcomes if o.rule_id.startswith("ENC")}
    assert all(o.passed for o in enc.values())


def test_summary_counts():
    checker = ComplianceChecker()
    outcomes = checker.run(_asset_with_services([]))
    summary = checker.summary(outcomes)
    assert summary["total"] == len(outcomes)
    assert summary["passed"] + summary["failed"] == summary["total"]
