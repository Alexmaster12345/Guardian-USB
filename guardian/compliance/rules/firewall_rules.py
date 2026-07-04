"""Firewall configuration compliance rules.

Context may include ``firewall`` dict: enabled(bool), default_policy(str),
allowed_ports(list[int]); and ``services`` list.
"""
from __future__ import annotations

from guardian.compliance.rules import Rule

FRAMEWORK = "Firewall-Policy"

_SENSITIVE_PORTS = {23, 135, 139, 445, 3389, 5900, 6379, 27017, 9200}


def _fw(context: dict) -> dict:
    return context.get("firewall") or {}


def _enabled(context: dict) -> tuple[bool, str]:
    enabled = bool(_fw(context).get("enabled", False))
    return enabled, f"firewall enabled={enabled}"


def _default_deny(context: dict) -> tuple[bool, str]:
    policy = str(_fw(context).get("default_policy", "allow")).lower()
    passed = policy in ("deny", "drop", "reject")
    return passed, f"default_policy={policy}"


def _no_sensitive_exposed(context: dict) -> tuple[bool, str]:
    exposed = [
        s.port for s in context.get("services", [])
        if getattr(s, "is_exposed", False) and s.port in _SENSITIVE_PORTS
    ]
    if exposed:
        return False, f"Sensitive ports exposed: {sorted(set(exposed))}"
    return True, "No sensitive ports exposed"


RULES = [
    Rule("FW-01", "Host firewall enabled", _enabled),
    Rule("FW-02", "Default-deny inbound policy", _default_deny),
    Rule("FW-03", "No sensitive ports exposed", _no_sensitive_exposed),
]
