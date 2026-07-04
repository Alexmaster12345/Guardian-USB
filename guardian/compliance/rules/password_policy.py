"""Password policy compliance rules.

Context may include ``password_policy`` dict with keys:
min_length, require_complexity, max_age_days, history, lockout_threshold.
"""
from __future__ import annotations

from guardian.compliance.rules import Rule

FRAMEWORK = "Password-Policy"


def _policy(context: dict) -> dict:
    return context.get("password_policy") or {}


def _min_length(context: dict) -> tuple[bool, str]:
    length = _policy(context).get("min_length", 0)
    return length >= 12, f"min_length={length} (require >=12)"


def _complexity(context: dict) -> tuple[bool, str]:
    complex_ = bool(_policy(context).get("require_complexity", False))
    return complex_, f"require_complexity={complex_}"


def _max_age(context: dict) -> tuple[bool, str]:
    age = _policy(context).get("max_age_days", 99999)
    return age <= 90, f"max_age_days={age} (require <=90)"


def _lockout(context: dict) -> tuple[bool, str]:
    threshold = _policy(context).get("lockout_threshold", 0)
    passed = 0 < threshold <= 10
    return passed, f"lockout_threshold={threshold} (require 1-10)"


def _history(context: dict) -> tuple[bool, str]:
    history = _policy(context).get("history", 0)
    return history >= 5, f"history={history} (require >=5)"


RULES = [
    Rule("PWD-01", "Minimum password length >= 12", _min_length),
    Rule("PWD-02", "Password complexity required", _complexity),
    Rule("PWD-03", "Maximum password age <= 90 days", _max_age),
    Rule("PWD-04", "Account lockout configured", _lockout),
    Rule("PWD-05", "Password history >= 5", _history),
]
