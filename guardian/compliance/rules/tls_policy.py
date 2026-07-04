"""TLS version and cipher policy compliance rules."""
from __future__ import annotations

from guardian.compliance.rules import Rule
from guardian.vulnerability_engine.checks.tls_checks import WEAK_CIPHER_KEYWORDS, WEAK_PROTOCOLS

FRAMEWORK = "TLS-Policy"


def _min_tls_version(context: dict) -> tuple[bool, str]:
    for svc in context.get("services", []):
        enc = getattr(svc, "encryption", None)
        if enc in WEAK_PROTOCOLS:
            return False, f"Service on port {svc.port} uses weak {enc}"
    return True, "No weak TLS protocol versions detected"


def _strong_ciphers(context: dict) -> tuple[bool, str]:
    ciphers = context.get("tls_ciphers", []) or []
    for cipher in ciphers:
        upper = str(cipher).upper()
        for kw in WEAK_CIPHER_KEYWORDS:
            if kw.upper() in upper:
                return False, f"Weak cipher present: {cipher}"
    return True, f"{len(ciphers)} ciphers reviewed, none weak"


def _https_available(context: dict) -> tuple[bool, str]:
    services = context.get("services", [])
    http = [s for s in services if (getattr(s, "service_name", "") or "").lower() == "http" and getattr(s, "encryption", None) is None]
    if http:
        ports = ", ".join(str(s.port) for s in http)
        return False, f"Plain HTTP without TLS on port(s): {ports}"
    return True, "No unencrypted HTTP services"


RULES = [
    Rule("TLS-01", "No deprecated TLS/SSL versions", _min_tls_version),
    Rule("TLS-02", "Strong cipher suites only", _strong_ciphers),
    Rule("TLS-03", "Web services enforce HTTPS", _https_available),
]
