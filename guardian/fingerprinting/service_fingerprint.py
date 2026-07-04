"""Match service banners to known products and versions."""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ServiceFingerprint:
    service_name: str | None
    vendor: str | None
    product: str | None
    version: str | None
    encryption: str | None = None


_BANNER_PATTERNS = [
    (re.compile(r"OpenSSH[_ ]([\w.\-p]+)", re.I), "ssh", "openbsd", "openssh"),
    (re.compile(r"Apache/([\d.]+)", re.I), "http", "apache", "http_server"),
    (re.compile(r"nginx/([\d.]+)", re.I), "http", "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS/([\d.]+)", re.I), "http", "microsoft", "iis"),
    (re.compile(r"lighttpd/([\d.]+)", re.I), "http", "lighttpd", "lighttpd"),
    (re.compile(r"(?:mysql|MariaDB).*?([\d.]+)", re.I), "mysql", "oracle", "mysql"),
    (re.compile(r"PostgreSQL ([\d.]+)", re.I), "postgresql", "postgresql", "postgresql"),
    (re.compile(r"vsFTPd ([\d.]+)", re.I), "ftp", "vsftpd", "vsftpd"),
    (re.compile(r"ProFTPD ([\d.]+)", re.I), "ftp", "proftpd", "proftpd"),
    (re.compile(r"Postfix", re.I), "smtp", "postfix", "postfix"),
    (re.compile(r"Exim ([\d.]+)", re.I), "smtp", "exim", "exim"),
    (re.compile(r"Redis.*?([\d.]+)", re.I), "redis", "redis", "redis"),
    (re.compile(r"log4j[- ]?([\d.]+)?", re.I), "log4j", "apache", "log4j"),
]


def fingerprint_service(
    banner: str | None,
    port: int | None = None,
    service_hint: str | None = None,
) -> ServiceFingerprint:
    """Parse a service banner into vendor/product/version."""
    text = banner or ""
    for pattern, svc, vendor, product in _BANNER_PATTERNS:
        m = pattern.search(text)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else None
            enc = "tls" if (port in (443, 993, 995, 8443) or "tls" in text.lower()) else None
            return ServiceFingerprint(
                service_name=svc, vendor=vendor, product=product, version=version, encryption=enc
            )

    return ServiceFingerprint(
        service_name=service_hint,
        vendor=None,
        product=service_hint,
        version=None,
        encryption="tls" if port in (443, 993, 995, 8443) else None,
    )
