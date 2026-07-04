"""Compliance rule modules."""
from dataclasses import dataclass
from typing import Callable


@dataclass
class Rule:
    id: str
    name: str
    evaluate: Callable[[dict], tuple[bool, str]]


def get_all_rule_modules():
    """Return all rule modules (lazy import to avoid circular imports)."""
    from guardian.compliance.rules import (
        ssh_hardening,
        tls_policy,
        password_policy,
        firewall_rules,
        disk_encryption,
    )
    return [ssh_hardening, tls_policy, password_policy, firewall_rules, disk_encryption]


__all__ = ["Rule", "get_all_rule_modules"]
