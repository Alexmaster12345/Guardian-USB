"""SSH hardening compliance rules.

Context dict may include ``sshd_config``: a dict of config directives,
and ``services``: list of Service objects.
"""
from __future__ import annotations

from guardian.compliance.rules import Rule

FRAMEWORK = "CIS-SSH"


def _get_config(context: dict) -> dict:
    cfg = context.get("sshd_config") or {}
    return {k.lower(): str(v).lower() for k, v in cfg.items()}


def _permit_root_login(context: dict) -> tuple[bool, str]:
    cfg = _get_config(context)
    val = cfg.get("permitrootlogin", "prohibit-password")
    passed = val in ("no", "prohibit-password", "without-password")
    return passed, f"PermitRootLogin={val}"


def _password_auth(context: dict) -> tuple[bool, str]:
    cfg = _get_config(context)
    val = cfg.get("passwordauthentication", "yes")
    passed = val == "no"
    return passed, f"PasswordAuthentication={val}"


def _protocol_version(context: dict) -> tuple[bool, str]:
    cfg = _get_config(context)
    val = cfg.get("protocol", "2")
    passed = val == "2"
    return passed, f"Protocol={val}"


def _default_port(context: dict) -> tuple[bool, str]:
    for svc in context.get("services", []):
        if (getattr(svc, "service_name", "") or "").lower() == "ssh":
            passed = svc.port != 22 or not getattr(svc, "is_exposed", False)
            return passed, f"SSH port {svc.port}, exposed={getattr(svc, 'is_exposed', False)}"
    return True, "No SSH service present"


RULES = [
    Rule("SSH-01", "Root login disabled or key-only", _permit_root_login),
    Rule("SSH-02", "Password authentication disabled", _password_auth),
    Rule("SSH-03", "SSH protocol version 2 enforced", _protocol_version),
    Rule("SSH-04", "SSH not exposed on default port to internet", _default_port),
]
