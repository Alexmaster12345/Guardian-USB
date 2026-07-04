"""Running-service and version detection from discovered ports."""
from __future__ import annotations

from guardian.core.models import Service
from guardian.discovery.network_scanner import DiscoveredHost, DiscoveredPort
from guardian.fingerprinting.service_fingerprint import fingerprint_service

_EXPOSED_PORTS = {21, 22, 23, 3389, 445, 3306, 5432, 6379, 1433, 27017}
_TLS_PORTS = {443, 993, 995, 8443, 465}


class ServiceDiscovery:
    """Converts discovered ports into Service model objects."""

    def services_for_host(self, host: DiscoveredHost, internet_facing: bool = False) -> list[Service]:
        services: list[Service] = []
        for port in host.ports:
            if port.state not in ("open", "open|filtered", "unknown"):
                continue
            services.append(self._to_service(port, internet_facing))
        return services

    def _to_service(self, port: DiscoveredPort, internet_facing: bool) -> Service:
        banner = port.banner or ""
        fp = fingerprint_service(banner=banner, port=port.port, service_hint=port.service_name)
        version = port.version or fp.version
        encryption = fp.encryption or ("tls" if port.port in _TLS_PORTS else None)
        is_exposed = internet_facing and port.port in (_EXPOSED_PORTS | {80, 443})
        return Service(
            port=port.port,
            protocol=port.protocol,
            service_name=fp.service_name or port.service_name,
            version=version,
            banner=banner or None,
            encryption=encryption,
            auth_method=self._auth_method(fp.service_name or port.service_name),
            is_exposed=is_exposed,
        )

    @staticmethod
    def _auth_method(service_name: str | None) -> str | None:
        if not service_name:
            return None
        s = service_name.lower()
        if s == "ssh":
            return "password/pubkey"
        if s in ("http", "https"):
            return "form/basic"
        if s in ("mysql", "postgresql", "mssql", "redis"):
            return "password"
        return None
