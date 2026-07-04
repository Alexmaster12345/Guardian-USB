"""Build CPE 2.3 strings from fingerprint / inventory data.

CPE 2.3 format:
  cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:<sw_edition>:<target_sw>:<target_hw>:<other>
"""
from __future__ import annotations

import re


def _norm(value: str | None) -> str:
    """Normalize a CPE component: lowercase, spaces->_, escape specials."""
    if not value:
        return "*"
    v = value.strip().lower().replace(" ", "_")
    v = re.sub(r"[^a-z0-9._\-]", "_", v)
    return v or "*"


def build_cpe(
    part: str,
    vendor: str | None,
    product: str | None,
    version: str | None = None,
    *,
    update: str = "*",
    edition: str = "*",
    language: str = "*",
    sw_edition: str = "*",
    target_sw: str = "*",
    target_hw: str = "*",
    other: str = "*",
) -> str:
    """Build a CPE 2.3 formatted string. `part` is a/o/h."""
    part = part if part in {"a", "o", "h"} else "a"
    fields = [
        "cpe", "2.3", part,
        _norm(vendor), _norm(product), _norm(version),
        update, edition, language, sw_edition, target_sw, target_hw, other,
    ]
    return ":".join(fields)


def build_cpe_from_software(software) -> str:
    """Build an application CPE from a Software ORM/dataclass object."""
    return build_cpe(
        "a",
        getattr(software, "vendor", None),
        getattr(software, "product", None),
        getattr(software, "version", None),
    )


def build_cpe_from_os(os_name: str | None, os_version: str | None, vendor: str | None = None) -> str:
    """Build an operating-system CPE."""
    guessed_vendor = vendor
    if not guessed_vendor and os_name:
        low = os_name.lower()
        if "windows" in low:
            guessed_vendor = "microsoft"
        elif "ubuntu" in low:
            guessed_vendor = "canonical"
        elif any(k in low for k in ("linux", "debian", "centos", "redhat", "red_hat")):
            guessed_vendor = low.split()[0]
    return build_cpe("o", guessed_vendor, os_name, os_version)


def cpe_matches(target_cpe: str, pattern_cpe: str) -> bool:
    """Return True if target_cpe matches pattern_cpe (with * wildcards)."""
    t = target_cpe.split(":")
    p = pattern_cpe.split(":")
    if len(t) < 6 or len(p) < 6:
        return False
    # Compare part, vendor, product, version (indices 2..5)
    for i in range(2, 6):
        pv = p[i]
        tv = t[i]
        if pv in ("*", "-"):
            continue
        if tv in ("*", "-"):
            continue
        if pv != tv:
            return False
    return True
