"""OS detection logic based on nmap output, TTL, and banner hints."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class OSFingerprint:
    os_name: str | None
    os_version: str | None
    vendor: str | None
    confidence: int  # 0-100


_TTL_HINTS = {
    64: ("Linux/Unix", "unix"),
    128: ("Windows", "microsoft"),
    255: ("Network Device", None),
}

_OS_PATTERNS = [
    (re.compile(r"windows server (\d{4})", re.I), "Windows Server", "microsoft"),
    (re.compile(r"windows (\d+(?:\.\d+)?)", re.I), "Windows", "microsoft"),
    (re.compile(r"ubuntu[ /]?(\d+\.\d+)?", re.I), "Ubuntu", "canonical"),
    (re.compile(r"debian[ /]?(\d+)?", re.I), "Debian", "debian"),
    (re.compile(r"centos[ /]?(\d+)?", re.I), "CentOS", "centos"),
    (re.compile(r"red hat[^\d]*(\d+)?", re.I), "Red Hat Enterprise Linux", "redhat"),
    (re.compile(r"linux (\d+\.\d+(?:\.\d+)?)", re.I), "Linux", "linux"),
    (re.compile(r"freebsd[ /]?(\d+\.\d+)?", re.I), "FreeBSD", "freebsd"),
    (re.compile(r"cisco ios[^\d]*(\d+\.\d+)?", re.I), "Cisco IOS", "cisco"),
]


def fingerprint_os(
    nmap_os_match: str | None = None,
    banner: str | None = None,
    ttl: int | None = None,
) -> OSFingerprint:
    """Best-effort OS fingerprint from available signals."""
    sources = " ".join(x for x in (nmap_os_match, banner) if x)

    for pattern, name, vendor in _OS_PATTERNS:
        m = pattern.search(sources)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else None
            return OSFingerprint(os_name=name, os_version=version, vendor=vendor, confidence=85)

    if ttl is not None:
        # TTL is decremented in transit; snap to nearest common base.
        for base in (64, 128, 255):
            if 0 < base - ttl <= 30 or ttl == base:
                name, vendor = _TTL_HINTS[base]
                return OSFingerprint(os_name=name, os_version=None, vendor=vendor, confidence=40)

    return OSFingerprint(os_name=None, os_version=None, vendor=None, confidence=0)
