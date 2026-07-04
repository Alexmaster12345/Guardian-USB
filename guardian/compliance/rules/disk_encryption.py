"""Disk / data-at-rest encryption compliance rules.

Context may include ``encryption`` dict: disk_encrypted(bool),
method(str e.g. LUKS/BitLocker), swap_encrypted(bool).
"""
from __future__ import annotations

from guardian.compliance.rules import Rule

FRAMEWORK = "Encryption-Policy"

_APPROVED_METHODS = {"luks", "bitlocker", "filevault", "dm-crypt"}


def _enc(context: dict) -> dict:
    return context.get("encryption") or {}


def _disk_encrypted(context: dict) -> tuple[bool, str]:
    enabled = bool(_enc(context).get("disk_encrypted", False))
    return enabled, f"disk_encrypted={enabled}"


def _approved_method(context: dict) -> tuple[bool, str]:
    method = str(_enc(context).get("method", "")).lower()
    if not method:
        return False, "No encryption method reported"
    passed = method in _APPROVED_METHODS
    return passed, f"method={method} (approved: {sorted(_APPROVED_METHODS)})"


def _swap_encrypted(context: dict) -> tuple[bool, str]:
    enabled = bool(_enc(context).get("swap_encrypted", False))
    return enabled, f"swap_encrypted={enabled}"


RULES = [
    Rule("ENC-01", "Full-disk encryption enabled", _disk_encrypted),
    Rule("ENC-02", "Approved encryption method in use", _approved_method),
    Rule("ENC-03", "Swap space encrypted", _swap_encrypted),
]
